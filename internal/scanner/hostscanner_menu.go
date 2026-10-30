package scanner

import (
	"fmt"
	"strings"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
)

func RunInteractiveHostScanner() {
	modes := []string{
		"Direct (HTTP/HTTPS + All Methods + Auto TLS/HTTP Switch + Raw Wire Fallback)",
		"DirectNon302 (Excludes 301/302/303/307/308 Redirects & Captive Portals)",
		"ProxyTest (WebSocket 101 Upgrade & Custom Payload / [split] DPI Fragmentation)",
		"ProxyRoute (Scan Targets Routed via Upstream HTTP Proxy)",
		"SSL / SNI (TLS 1.0-1.3 Handshake, ALPN, Cert Subject/Issuer & Custom SNI)",
		"Ping (Multi-Port TCP Reachability & Millisecond Latency)",
	}
	modeChoice := banner.PromptChoice("Select Host Scanning Mode", modes, 0)

	spec, err := input.PromptTargetSpec()
	if err != nil || spec == nil {
		return
	}

	switch {
	case strings.HasPrefix(modeChoice, "Direct"):
		no302 := strings.HasPrefix(modeChoice, "DirectNon302")
		portsRaw := banner.PromptText("Enter port(s) or range (e.g. 80,443,8080,8443)", "80,443", true)
		ports := input.ParsePorts(portsRaw)
		methods := banner.PromptMethods()
		customHost := banner.PromptText("Optional spoofed Host header (press Enter for target's own host)", "", false)
		customSNI := banner.PromptText("Optional spoofed TLS SNI (press Enter for target's own host)", "", false)
		timeoutSec := banner.PromptInt("Enter timeout per attempt (seconds)", 4, 1)
		retries := banner.PromptInt("Enter automatic retries on timeout (prevents skipping slow hosts)", 2, 0)
		workers := banner.PromptInt("Enter concurrent goroutines", 150, 1)
		outFile := banner.PromptText("Enter output filename", "results.txt", true)

		runner := NewDirectScanner(spec, methods, ports, no302, timeoutSec, retries, customHost, customSNI)
		engine := NewEngine(workers, outFile)
		engine.Run(runner)

	case strings.HasPrefix(modeChoice, "ProxyTest"):
		targetURL := banner.PromptText("Enter target Host/SNI for [host] placeholder", "in1.wstunnel.site", true)
		defaultPayload := "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
		fmt.Printf("   %sTip: Placeholders: [host], [proxy], [ip], [port], [ua], [crlf], [split] (TCP fragment)%s\n", banner.Gray, banner.Reset)
		payload := banner.PromptText("Enter payload", defaultPayload, true)
		portsRaw := banner.PromptText("Enter port(s) (e.g. 80,443,8080,8443)", "80,443", true)
		ports := input.ParsePorts(portsRaw)
		timeoutSec := banner.PromptInt("Enter timeout (seconds)", 4, 1)
		retries := banner.PromptInt("Enter retries on timeout", 2, 0)
		workers := banner.PromptInt("Enter concurrent goroutines", 150, 1)
		outFile := banner.PromptText("Enter output filename", "results_proxy.txt", true)

		runner := NewProxyCheckScanner(spec, ports, targetURL, payload, timeoutSec, retries)
		engine := NewEngine(workers, outFile)
		engine.Run(runner)

	case strings.HasPrefix(modeChoice, "ProxyRoute"):
		portsRaw := banner.PromptText("Enter target port(s)", "80,443", true)
		ports := input.ParsePorts(portsRaw)
		methods := banner.PromptMethods()
		proxyAddr := banner.PromptText("Enter upstream proxy (host:port)", "", true)
		var user, pass string
		if banner.PromptConfirm("Use proxy authentication?", false) {
			user = banner.PromptText("Enter proxy username", "", true)
			pass = banner.PromptText("Enter proxy password", "", true)
		}
		no302 := banner.PromptConfirm("Exclude 301/302 redirects?", false)
		timeoutSec := banner.PromptInt("Enter timeout (seconds)", 5, 1)
		retries := banner.PromptInt("Enter retries on timeout", 2, 0)
		workers := banner.PromptInt("Enter concurrent goroutines", 100, 1)
		outFile := banner.PromptText("Enter output filename", "results_proxyroute.txt", true)

		runner, err := NewProxyRouteScanner(spec, methods, ports, proxyAddr, user, pass, no302, timeoutSec, retries)
		if err != nil {
			fmt.Printf(" %s[!] Invalid proxy URL: %v%s\n", banner.Red, err, banner.Reset)
			return
		}
		engine := NewEngine(workers, outFile)
		engine.Run(runner)

	case strings.HasPrefix(modeChoice, "SSL"):
		portsRaw := banner.PromptText("Enter TLS port(s) (e.g. 443,8443,2053,2083,2087,2096)", "443", true)
		ports := input.ParsePorts(portsRaw)
		customSNI := banner.PromptText("Optional spoofed SNI hostname (press Enter for target's own host)", "", false)
		timeoutSec := banner.PromptInt("Enter timeout (seconds)", 4, 1)
		retries := banner.PromptInt("Enter retries on timeout", 2, 0)
		workers := banner.PromptInt("Enter concurrent goroutines", 150, 1)
		outFile := banner.PromptText("Enter output filename", "results_ssl.txt", true)

		runner := NewSSLScanner(spec, ports, customSNI, timeoutSec, retries)
		engine := NewEngine(workers, outFile)
		engine.Run(runner)

	case strings.HasPrefix(modeChoice, "Ping"):
		portsRaw := banner.PromptText("Enter TCP port(s) to ping", "80,443", true)
		ports := input.ParsePorts(portsRaw)
		timeoutSec := banner.PromptInt("Enter timeout (seconds)", 3, 1)
		retries := banner.PromptInt("Enter retries on timeout", 2, 0)
		workers := banner.PromptInt("Enter concurrent goroutines", 200, 1)
		outFile := banner.PromptText("Enter output filename", "results_ping.txt", true)

		runner := NewPingScanner(spec, ports, timeoutSec, retries)
		engine := NewEngine(workers, outFile)
		engine.Run(runner)
	}
}
