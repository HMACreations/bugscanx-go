package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type SSLJob struct {
	Host string
	Port string
}

type SSLScanner struct {
	TargetSpec *input.TargetSpec
	Ports      []string
	CustomSNI  string
	Timeout    time.Duration
	Retries    int
}

func NewSSLScanner(spec *input.TargetSpec, ports []string, customSNI string, timeoutSec, retries int) *SSLScanner {
	if len(ports) == 0 {
		ports = []string{"443"}
	}
	if timeoutSec <= 0 {
		timeoutSec = 4
	}
	if retries < 0 {
		retries = 2
	}
	return &SSLScanner{
		TargetSpec: spec,
		Ports:      ports,
		CustomSNI:  strings.TrimSpace(customSNI),
		Timeout:    time.Duration(timeoutSec) * time.Second,
		Retries:    retries,
	}
}

func (ss *SSLScanner) TotalJobs() int64 {
	return ss.TargetSpec.CountTargets() * int64(len(ss.Ports))
}

func (ss *SSLScanner) MetadataDescription() string {
	return fmt.Sprintf("Mode: SSL/SNI | %s | Ports: %s", ss.TargetSpec.Description, strings.Join(ss.Ports, ","))
}

func (ss *SSLScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-8s%s  %s%-6s%s  %s%-6s%s  %s%-16s%s  %s%-24s%s  %s%s%s",
		banner.Cyan, "TLS Ver", banner.Reset,
		banner.Green, "ALPN", banner.Reset,
		banner.Orange, "Port", banner.Reset,
		banner.Yellow, "IP", banner.Reset,
		banner.Magenta, "Cert Subject / Issuer", banner.Reset,
		banner.White, "SNI / Host", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-8s%s  %s%-6s%s  %s%-6s%s  %s%-16s%s  %s%-24s%s  %s%s%s",
		banner.Cyan, "--------", banner.Reset,
		banner.Green, "------", banner.Reset,
		banner.Orange, "------", banner.Reset,
		banner.Yellow, "----------------", banner.Reset,
		banner.Magenta, "------------------------", banner.Reset,
		banner.White, "--------------------", banner.Reset,
	)
	return []string{h1, h2}
}

func (ss *SSLScanner) ProduceJobs(emit func(job any) bool) {
	ss.TargetSpec.StreamTargets(func(host string) bool {
		for _, port := range ss.Ports {
			if !emit(SSLJob{Host: host, Port: port}) {
				return false
			}
		}
		return true
	})
}

func (ss *SSLScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(SSLJob)
	engine.SetCurrentStatus(fmt.Sprintf("SSL %s:%s", job.Host, job.Port))

	ips, err := resolver.Default.ResolveAll(job.Host)
	if err != nil || len(ips) == 0 {
		return
	}

	maxIPs := len(ips)
	if maxIPs > 2 {
		maxIPs = 2
	}

	for i := 0; i < maxIPs; i++ {
		ip := ips[i]
		for attempt := 0; attempt <= ss.Retries; attempt++ {
			timeout := ss.Timeout + time.Duration(attempt)*time.Second
			rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, job.Port), timeout)
			if err != nil {
				continue
			}
			_ = rawConn.SetDeadline(time.Now().Add(timeout))

			tlsCfg := buildPermissiveTLSConfig(job.Host, ss.CustomSNI)
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
			tlsConn := tls.Client(rawConn, tlsCfg)
			err = tlsConn.Handshake()
			if err != nil {
				_ = rawConn.Close()
				continue
			}

			state := tlsConn.ConnectionState()
			tlsVer := tlsVersionString(state.Version)
			alpn := state.NegotiatedProtocol
			if alpn == "" {
				alpn = "http/1"
			}

			certInfo := "-"
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				cn := cert.Subject.CommonName
				if cn == "" && len(cert.DNSNames) > 0 {
					cn = cert.DNSNames[0]
				}
				issuer := ""
				if len(cert.Issuer.Organization) > 0 {
					issuer = cert.Issuer.Organization[0]
				} else {
					issuer = cert.Issuer.CommonName
				}
				if issuer != "" {
					certInfo = fmt.Sprintf("%s (%s)", cn, issuer)
				} else {
					certInfo = cn
				}
			}
			if len(certInfo) > 24 {
				certInfo = certInfo[:21] + "..."
			}
			_ = tlsConn.Close()

			sniDisplay := job.Host
			if ss.CustomSNI != "" {
				sniDisplay = fmt.Sprintf("%s (SNI:%s)", job.Host, ss.CustomSNI)
			}

			colored := fmt.Sprintf(
				"%s%-8s%s  %s%-6s%s  %s%-6s%s  %s%-16s%s  %s%-24s%s  %s%s%s",
				banner.Cyan, tlsVer, banner.Reset,
				banner.Green, alpn, banner.Reset,
				banner.Orange, job.Port, banner.Reset,
				banner.Yellow, ip, banner.Reset,
				banner.Magenta, certInfo, banner.Reset,
				banner.White, sniDisplay, banner.Reset,
			)
			plain := fmt.Sprintf("%-8s  %-6s  %-6s  %-16s  %-24s  %s",
				tlsVer, alpn, job.Port, ip, certInfo, sniDisplay)
			engine.RecordSuccess(colored, plain)
			return
		}
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
