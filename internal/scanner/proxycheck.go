package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type ProxyCheckJob struct {
	ProxyHost string
	Port      string
}

type ProxyCheckScanner struct {
	TargetSpec *input.TargetSpec
	Ports      []string
	TargetSNI  string // Target host for [host] placeholder and SNI
	Payload    string
	Timeout    time.Duration
	Retries    int
}

func NewProxyCheckScanner(spec *input.TargetSpec, ports []string, targetHost, payload string, timeoutSec, retries int) *ProxyCheckScanner {
	if timeoutSec <= 0 {
		timeoutSec = 4
	}
	if retries < 0 {
		retries = 2
	}
	if payload == "" {
		payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
	}
	return &ProxyCheckScanner{
		TargetSpec: spec,
		Ports:      ports,
		TargetSNI:  strings.TrimSpace(targetHost),
		Payload:    payload,
		Timeout:    time.Duration(timeoutSec) * time.Second,
		Retries:    retries,
	}
}

func (ps *ProxyCheckScanner) TotalJobs() int64 {
	return ps.TargetSpec.CountTargets() * int64(len(ps.Ports))
}

func (ps *ProxyCheckScanner) MetadataDescription() string {
	return fmt.Sprintf("Mode: ProxyTest (WebSocket/Payload) | %s | Target: %s | Ports: %s",
		ps.TargetSpec.Description, ps.TargetSNI, strings.Join(ps.Ports, ","))
}

func (ps *ProxyCheckScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-28s%s  %s%-16s%s  %s%-6s%s  %s%-6s%s  %s%s%s",
		banner.Cyan, "ProxyHost:Port", banner.Reset,
		banner.Blue, "Resolved IP", banner.Reset,
		banner.Yellow, "Proto", banner.Reset,
		banner.Green, "Code", banner.Reset,
		banner.White, "Status / Server Response", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-28s%s  %s%-16s%s  %s%-6s%s  %s%-6s%s  %s%s%s",
		banner.Cyan, "----------------------------", banner.Reset,
		banner.Blue, "----------------", banner.Reset,
		banner.Yellow, "------", banner.Reset,
		banner.Green, "------", banner.Reset,
		banner.White, "--------------------------------", banner.Reset,
	)
	return []string{h1, h2}
}

func (ps *ProxyCheckScanner) ProduceJobs(emit func(job any) bool) {
	ps.TargetSpec.StreamTargets(func(target string) bool {
		for _, port := range ps.Ports {
			if !emit(ProxyCheckJob{
				ProxyHost: target,
				Port:      port,
			}) {
				return false
			}
		}
		return true
	})
}

func (ps *ProxyCheckScanner) formatPayload(proxyHost, ip, port string) string {
	target := ps.TargetSNI
	if target == "" {
		target = proxyHost
	}
	replacer := strings.NewReplacer(
		"[host]", target,
		"[proxy]", proxyHost,
		"[ip]", ip,
		"[port]", port,
		"[ua]", config.RandomUserAgent(),
		"[crlf]", "\r\n",
		"[cr]", "\r",
		"[lf]", "\n",
	)
	out := replacer.Replace(ps.Payload)
	if !strings.HasSuffix(out, "\r\n\r\n") && !strings.HasSuffix(out, "\n\n") {
		out += "\r\n\r\n"
	}
	return out
}

func (ps *ProxyCheckScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(ProxyCheckJob)
	hostPort := fmt.Sprintf("%s:%s", job.ProxyHost, job.Port)
	engine.SetCurrentStatus("WS/Proxy " + hostPort)

	ips, err := resolver.Default.ResolveAll(job.ProxyHost)
	if err != nil || len(ips) == 0 {
		return
	}

	primaryTLS := config.StandardTLSPorts[job.Port]
	schemes := []bool{primaryTLS, !primaryTLS}

	maxIPs := len(ips)
	if maxIPs > 2 {
		maxIPs = 2
	}

	for i := 0; i < maxIPs; i++ {
		ip := ips[i]
		for sIdx, useTLS := range schemes {
			code, proto, headers, tryOpposite := ps.probePayloadWithRetries(job.ProxyHost, ip, job.Port, useTLS)
			if code != "" && code != "N/A" && code != "302" {
				ps.recordProxyHit(hostPort, ip, proto, code, headers, engine)
				return
			}
			if sIdx == 0 && !tryOpposite {
				break
			}
		}
	}
}

func (ps *ProxyCheckScanner) probePayloadWithRetries(proxyHost, ip, port string, useTLS bool) (string, string, []string, bool) {
	maxAttempts := 1 + ps.Retries
	for attempt := 0; attempt < maxAttempts; attempt++ {
		timeout := ps.Timeout + time.Duration(attempt)*time.Second
		code, proto, headers, mismatch := ps.probeOnce(proxyHost, ip, port, useTLS, timeout)
		if code != "" {
			return code, proto, headers, false
		}
		if mismatch {
			return "", "", nil, true
		}
	}
	return "", "", nil, false
}

func (ps *ProxyCheckScanner) probeOnce(proxyHost, ip, port string, useTLS bool, timeout time.Duration) (string, string, []string, bool) {
	targetAddr := net.JoinHostPort(ip, port)
	rawConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return "", "", nil, false
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	var conn net.Conn = rawConn
	proto := "WS/TCP"
	if useTLS {
		proto = "WSS/TLS"
		sni := ps.TargetSNI
		if sni == "" {
			sni = proxyHost
		}
		tlsConn := tls.Client(rawConn, buildPermissiveTLSConfig(proxyHost, sni))
		if err := tlsConn.Handshake(); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "first record does not look like a tls handshake") {
				return "", "", nil, true
			}
			return "", "", nil, false
		}
		conn = tlsConn
	}

	formatted := ps.formatPayload(proxyHost, ip, port)
	// Support [split] for DPI packet fragmentation!
	segments := strings.Split(formatted, "[split]")
	for idx, seg := range segments {
		if seg == "" {
			continue
		}
		if _, err := conn.Write([]byte(seg)); err != nil {
			return "", "", nil, false
		}
		if idx < len(segments)-1 {
			time.Sleep(15 * time.Millisecond)
		}
	}

	// CRITICAL FIX over Python BugScanX:
	// Read headers line-by-line up to empty line (\r\n\r\n), DO NOT block until EOF!
	// Working 101 Switching Protocols servers keep the socket open for tunnel frames.
	reader := bufio.NewReaderSize(conn, 8192)
	statusLine, err := reader.ReadString('\n')
	if err != nil && len(statusLine) == 0 {
		return "", "", nil, false
	}
	statusLine = strings.TrimSpace(statusLine)
	if len(statusLine) >= 2 && statusLine[0] == 0x15 && statusLine[1] == 0x03 {
		return "", "", nil, true
	}
	if !strings.HasPrefix(statusLine, "HTTP/") {
		return "", "", nil, false
	}

	parts := strings.SplitN(statusLine, " ", 3)
	statusCode := "N/A"
	if len(parts) >= 2 {
		statusCode = parts[1]
	}

	responseLines := []string{statusLine}
	for i := 0; i < 40; i++ {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break // Reached \r\n\r\n end of HTTP headers! Return immediately!
		}
		responseLines = append(responseLines, line)
		if err != nil {
			break
		}
	}

	if !useTLS && statusCode == "400" {
		joined := strings.ToLower(strings.Join(responseLines, " "))
		if strings.Contains(joined, "https port") || strings.Contains(joined, "ssl") {
			return "", "", nil, true
		}
	}

	return statusCode, proto, responseLines, false
}

func (ps *ProxyCheckScanner) recordProxyHit(hostPort, ip, proto, code string, lines []string, engine *Engine) {
	color := banner.Gray
	if code == "101" {
		color = banner.Bold + banner.Green
	} else if strings.HasPrefix(code, "2") {
		color = banner.Cyan
	} else if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
		color = banner.Yellow
	}

	summary := ""
	if len(lines) > 0 {
		summary = lines[0]
	}
	for _, l := range lines[1:] {
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "server:") || strings.HasPrefix(ll, "upgrade:") || strings.HasPrefix(ll, "cf-ray:") || strings.HasPrefix(ll, "via:") {
			summary += " | " + l
		}
	}

	colored := fmt.Sprintf(
		"%s%-28s%s  %s%-16s%s  %s%-6s%s  %s%-6s%s  %s%s%s",
		color, hostPort, banner.Reset,
		banner.Blue, ip, banner.Reset,
		banner.Yellow, proto, banner.Reset,
		color, code, banner.Reset,
		color, summary, banner.Reset,
	)
	plain := fmt.Sprintf("%-28s  %-16s  %-6s  %-6s  %s", hostPort, ip, proto, code, summary)
	engine.RecordSuccess(colored, plain)
}
