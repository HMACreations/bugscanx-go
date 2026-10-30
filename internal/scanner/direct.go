package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type DirectJob struct {
	Method string
	Host   string
	Port   string
}

type DirectProbeResult struct {
	Method     string
	Host       string
	IP         string
	Port       string
	Scheme     string
	StatusCode int
	StatusText string
	Server     string
	Location   string
}

type DirectScanner struct {
	TargetSpec *input.TargetSpec
	Methods    []string
	Ports      []string
	No302      bool
	Timeout    time.Duration
	Retries    int
	CustomHost string // Optional spoofed Host header
	CustomSNI  string // Optional spoofed TLS SNI
}

func NewDirectScanner(spec *input.TargetSpec, methods, ports []string, no302 bool, timeoutSec, retries int, customHost, customSNI string) *DirectScanner {
	if timeoutSec <= 0 {
		timeoutSec = 4
	}
	if retries < 0 {
		retries = 2
	}
	return &DirectScanner{
		TargetSpec: spec,
		Methods:    methods,
		Ports:      ports,
		No302:      no302,
		Timeout:    time.Duration(timeoutSec) * time.Second,
		Retries:    retries,
		CustomHost: strings.TrimSpace(customHost),
		CustomSNI:  strings.TrimSpace(customSNI),
	}
}

func (ds *DirectScanner) TotalJobs() int64 {
	targets := ds.TargetSpec.CountTargets()
	return targets * int64(len(ds.Ports)) * int64(len(ds.Methods))
}

func (ds *DirectScanner) MetadataDescription() string {
	mode := "Direct"
	if ds.No302 {
		mode = "DirectNon302"
	}
	return fmt.Sprintf("Mode: %s | %s | Ports: %s | Methods: %s",
		mode, ds.TargetSpec.Description, strings.Join(ds.Ports, ","), strings.Join(ds.Methods, ","))
}

func (ds *DirectScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-10s%s  %s%-5s%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "Method", banner.Reset,
		banner.Green, "Code", banner.Reset,
		banner.Yellow, "Proto", banner.Reset,
		banner.Magenta, "Server", banner.Reset,
		banner.Orange, "Port", banner.Reset,
		banner.Blue, "IP", banner.Reset,
		banner.White, "Host", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-10s%s  %s%-5s%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "----------", banner.Reset,
		banner.Green, "-----", banner.Reset,
		banner.Yellow, "------", banner.Reset,
		banner.Magenta, "----------------", banner.Reset,
		banner.Orange, "------", banner.Reset,
		banner.Blue, "----------------", banner.Reset,
		banner.White, "--------------------", banner.Reset,
	)
	return []string{h1, h2}
}

// ProduceJobs orders jobs by Target -> Port -> Method so DNS cache is hot for all methods on the same host!
func (ds *DirectScanner) ProduceJobs(emit func(job any) bool) {
	ds.TargetSpec.StreamTargets(func(host string) bool {
		for _, port := range ds.Ports {
			for _, method := range ds.Methods {
				if !emit(DirectJob{
					Method: strings.ToUpper(strings.TrimSpace(method)),
					Host:   host,
					Port:   port,
				}) {
					return false
				}
			}
		}
		return true
	})
}

func (ds *DirectScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(DirectJob)
	engine.SetCurrentStatus(fmt.Sprintf("%s %s:%s", job.Method, job.Host, job.Port))

	// Resolve all candidate IPs (never drops on single UDP packet loss)
	ips, err := resolver.Default.ResolveAll(job.Host)
	if err != nil || len(ips) == 0 {
		return
	}

	// Determine primary scheme for this port, and fallback scheme if protocol mismatch occurs
	primaryTLS := config.StandardTLSPorts[job.Port]
	schemes := []bool{primaryTLS, !primaryTLS}

	// Try candidate IPs (up to 3 if round-robin DNS returns multiple A records)
	maxIPs := len(ips)
	if maxIPs > 3 {
		maxIPs = 3
	}

	for ipIdx := 0; ipIdx < maxIPs; ipIdx++ {
		targetIP := ips[ipIdx]
		for schemeIdx, useTLS := range schemes {
			// Only try the opposite scheme if schemeIdx == 0 OR if the first scheme failed/hinted at protocol mismatch
			res, shouldTryOppositeScheme := ds.probeWithRetries(job.Method, job.Host, targetIP, job.Port, useTLS)
			if res != nil {
				ds.handleHit(res, engine)
				return
			}
			if schemeIdx == 0 && !shouldTryOppositeScheme {
				break
			}
		}
	}
}

// probeWithRetries performs up to (1 + ds.Retries) attempts, falling back to raw wire socket probing if net/http rejects non-standard responses.
func (ds *DirectScanner) probeWithRetries(method, host, ip, port string, useTLS bool) (*DirectProbeResult, bool) {
	maxAttempts := 1 + ds.Retries
	tryOppositeScheme := false

	for attempt := 0; attempt < maxAttempts; attempt++ {
		attemptTimeout := ds.Timeout + time.Duration(attempt)*1500*time.Millisecond

		// CONNECT and PRI (or custom raw verbs) are best handled directly via raw wire probe
		if method == "CONNECT" || method == "PRI" {
			res, mismatch := ds.probeRawWire(method, host, ip, port, useTLS, attemptTimeout)
			if res != nil {
				return res, false
			}
			if mismatch {
				return nil, true
			}
			continue
		}

		res, mismatch, err := ds.probeStdHTTP(method, host, ip, port, useTLS, attemptTimeout)
		if res != nil {
			// Check if plain HTTP was sent to an HTTPS port (e.g., 400 Bad Request on Nginx/Cloudflare)
			if !useTLS && res.StatusCode == 400 {
				return res, true
			}
			return res, false
		}
		if mismatch {
			tryOppositeScheme = true
			break // Immediately switch HTTP <-> HTTPS
		}

		// If net/http failed due to malformed headers or strict RFC parsing (not a simple dial timeout),
		// immediately test with our Raw Wire Prober so non-standard servers are NEVER skipped!
		if err != nil && !isTimeoutOrRefused(err) {
			rawRes, rawMismatch := ds.probeRawWire(method, host, ip, port, useTLS, attemptTimeout)
			if rawRes != nil {
				return rawRes, false
			}
			if rawMismatch {
				tryOppositeScheme = true
				break
			}
		}

		if attempt < maxAttempts-1 {
			time.Sleep(time.Duration(attempt+1) * 80 * time.Millisecond)
		}
	}

	return nil, tryOppositeScheme
}

func buildPermissiveTLSConfig(host, customSNI string) *tls.Config {
	sni := customSNI
	if sni == "" {
		// RFC 6066: Literal IP addresses are not permitted in SNI HostName
		if _, err := netip.ParseAddr(host); err != nil {
			sni = host
		}
	}

	// Include both standard and legacy cipher suites so older TLS 1.0/1.1 servers never fail handshake
	var allCiphers []uint16
	for _, cs := range tls.CipherSuites() {
		allCiphers = append(allCiphers, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		allCiphers = append(allCiphers, cs.ID)
	}

	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       allCiphers,
	}
}

func (ds *DirectScanner) probeStdHTTP(method, host, ip, port string, useTLS bool, timeout time.Duration) (*DirectProbeResult, bool, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	hostHeader := host
	if ds.CustomHost != "" {
		hostHeader = ds.CustomHost
	}
	if (port != "80" && !useTLS) || (port != "443" && useTLS) {
		if !strings.Contains(hostHeader, ":") {
			hostHeader = fmt.Sprintf("%s:%s", hostHeader, port)
		}
	}

	targetAddr := net.JoinHostPort(ip, port)
	urlStr := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, port))

	tlsCfg := buildPermissiveTLSConfig(host, ds.CustomSNI)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: -1,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}
	// Dial the resolved IP directly so DNS isn't looked up a second time
	transport.DialTLSContext = nil
	origDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return origDial(ctx, network, targetAddr)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		return nil, false, err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", config.RandomUserAgent())
	for k, v := range config.DefaultBrowserHeaders {
		req.Header.Set(k, v)
	}
	if config.MethodNeedsContentLengthZero(method) {
		req.Header.Set("Content-Length", "0")
		req.ContentLength = 0
	}

	resp, err := client.Do(req)
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "first record does not look like a tls handshake") ||
			strings.Contains(errMsg, "http response to https client") ||
			strings.Contains(errMsg, "malformed http") {
			return nil, true, err
		}
		return nil, false, err
	}
	defer resp.Body.Close()

	// Read a small snippet if status is 400 over plain HTTP to check if port actually expects HTTPS
	if !useTLS && resp.StatusCode == 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if strings.Contains(strings.ToLower(string(snippet)), "https port") ||
			strings.Contains(strings.ToLower(string(snippet)), "ssl") {
			return nil, true, nil
		}
	}

	return &DirectProbeResult{
		Method:     method,
		Host:       host,
		IP:         ip,
		Port:       port,
		Scheme:     strings.ToUpper(scheme),
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Server:     resp.Header.Get("Server"),
		Location:   resp.Header.Get("Location"),
	}, false, nil
}

// probeRawWire sends a raw HTTP/1.1 request over TCP or TLS and parses the response status line & headers.
// This catches servers with non-RFC headers, custom methods (QUERY, PRI, CONNECT, WebDAV), and WebSocket endpoints.
func (ds *DirectScanner) probeRawWire(method, host, ip, port string, useTLS bool, timeout time.Duration) (*DirectProbeResult, bool) {
	targetAddr := net.JoinHostPort(ip, port)
	rawConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return nil, false
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	var conn net.Conn = rawConn
	scheme := "HTTP"
	if useTLS {
		scheme = "HTTPS"
		tlsConn := tls.Client(rawConn, buildPermissiveTLSConfig(host, ds.CustomSNI))
		if err := tlsConn.Handshake(); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "first record does not look like a tls handshake") {
				return nil, true
			}
			return nil, false
		}
		conn = tlsConn
	}

	hostHeader := host
	if ds.CustomHost != "" {
		hostHeader = ds.CustomHost
	}

	var reqBuilder strings.Builder
	if method == "CONNECT" {
		authority := fmt.Sprintf("%s:%s", hostHeader, port)
		reqBuilder.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
			authority, authority, config.RandomUserAgent()))
	} else {
		reqBuilder.WriteString(fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n",
			method, hostHeader, config.RandomUserAgent()))
		if config.MethodNeedsContentLengthZero(method) {
			reqBuilder.WriteString("Content-Length: 0\r\n")
		}
		reqBuilder.WriteString("\r\n")
	}

	if _, err := conn.Write([]byte(reqBuilder.String())); err != nil {
		return nil, false
	}

	reader := bufio.NewReaderSize(conn, 8192)
	statusLine, err := reader.ReadString('\n')
	if err != nil && len(statusLine) == 0 {
		return nil, false
	}
	statusLine = strings.TrimSpace(statusLine)
	if len(statusLine) >= 2 && statusLine[0] == 0x15 && statusLine[1] == 0x03 {
		// Server responded with a raw TLS Alert to plain HTTP request!
		return nil, true
	}
	if !strings.HasPrefix(statusLine, "HTTP/") && !strings.HasPrefix(statusLine, "ICY ") {
		return nil, false
	}

	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, false
	}
	var code int
	_, err = fmt.Sscanf(parts[1], "%d", &code)
	if err != nil || code < 100 || code > 999 {
		return nil, false
	}

	serverHdr := ""
	locationHdr := ""
	for i := 0; i < 64; i++ {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if kv := strings.SplitN(line, ":", 2); len(kv) == 2 {
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			v := strings.TrimSpace(kv[1])
			if k == "server" && serverHdr == "" {
				serverHdr = v
			} else if k == "location" && locationHdr == "" {
				locationHdr = v
			}
		}
		if err != nil {
			break
		}
	}

	return &DirectProbeResult{
		Method:     method,
		Host:       host,
		IP:         ip,
		Port:       port,
		Scheme:     scheme,
		StatusCode: code,
		StatusText: statusLine,
		Server:     serverHdr,
		Location:   locationHdr,
	}, false
}

func (ds *DirectScanner) handleHit(res *DirectProbeResult, engine *Engine) {
	if ds.No302 {
		if res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 303 || res.StatusCode == 307 || res.StatusCode == 308 {
			return
		}
		if config.IsExcludedLocation(res.Location) {
			return
		}
	} else {
		if config.IsExcludedLocation(res.Location) {
			return
		}
	}

	srv := res.Server
	if srv == "" {
		srv = "-"
	} else if len(srv) > 14 {
		srv = srv[:11] + "..."
	}

	codeColor := banner.Green
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		codeColor = banner.Yellow
	} else if res.StatusCode >= 400 && res.StatusCode < 500 {
		codeColor = banner.Cyan
	} else if res.StatusCode >= 500 {
		codeColor = banner.Red
	}

	hostDisplay := res.Host
	if !ds.No302 && res.Location != "" {
		locShort := res.Location
		if len(locShort) > 35 {
			locShort = locShort[:32] + "..."
		}
		hostDisplay = fmt.Sprintf("%s -> %s", res.Host, locShort)
	}

	colored := fmt.Sprintf(
		"%s%-10s%s  %s%-5d%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, res.Method, banner.Reset,
		codeColor, res.StatusCode, banner.Reset,
		banner.Yellow, res.Scheme, banner.Reset,
		banner.Magenta, srv, banner.Reset,
		banner.Orange, res.Port, banner.Reset,
		banner.Blue, res.IP, banner.Reset,
		banner.White, hostDisplay, banner.Reset,
	)
	plain := fmt.Sprintf(
		"%-10s  %-5d  %-6s  %-16s  %-6s  %-16s  %s",
		res.Method, res.StatusCode, res.Scheme, srv, res.Port, res.IP, hostDisplay,
	)
	engine.RecordSuccess(colored, plain)
}

func isTimeoutOrRefused(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "network is unreachable")
}
