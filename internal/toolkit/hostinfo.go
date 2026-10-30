package toolkit

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
	"github.com/FreeNetLabs/bugscanx-go/internal/scanner"
)

func detectCDNs(headers http.Header, cnamesAndPTRs []string) []string {
	detected := make(map[string]bool)
	lowerHeaders := make(map[string]string)
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = strings.ToLower(strings.Join(v, ", "))
	}
	serverVal := lowerHeaders["server"]

	for provider, ind := range config.CDNProviders {
		// 1. Exact header match
		for _, h := range ind.Headers {
			if _, ok := lowerHeaders[strings.ToLower(h)]; ok {
				detected[provider] = true
				break
			}
		}
		if detected[provider] {
			continue
		}

		// 2. Header prefix match (fixes Python bug where 'x-cf-', 'ali-cdn-', 'x-oss-' never matched!)
		for _, pfx := range ind.HeaderPrefix {
			pfxLower := strings.ToLower(pfx)
			for hk := range lowerHeaders {
				if strings.HasPrefix(hk, pfxLower) {
					detected[provider] = true
					break
				}
			}
			if detected[provider] {
				break
			}
		}
		if detected[provider] {
			continue
		}

		// 3. Server header substring match
		for _, srvSub := range ind.ServerSubstrs {
			if strings.Contains(serverVal, strings.ToLower(srvSub)) {
				detected[provider] = true
				break
			}
		}
		if detected[provider] {
			continue
		}

		// 4. CNAME & PTR pattern match
		for _, cname := range cnamesAndPTRs {
			cLower := strings.ToLower(cname)
			for _, pat := range ind.CNAMEPatterns {
				if strings.Contains(cLower, strings.ToLower(pat)) {
					detected[provider] = true
					break
				}
			}
		}
	}

	var out []string
	for p := range detected {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func RunInteractiveHostInfo() {
	rawHost := banner.PromptText("Enter target host or IP", "", true)
	host := input.NormalizeHost(rawHost)
	if host == "" {
		host = rawHost
	}

	proto := banner.PromptChoice("Select primary protocol", []string{"https", "http"}, 0)
	portDefault := "443"
	if proto == "http" {
		portDefault = "80"
	}
	port := banner.PromptText("Enter port", portDefault, true)
	methods := banner.PromptMethods()

	// 1. Resolve all IPs + CNAME + PTR
	ips, err := resolver.Default.ResolveAll(host)
	if err != nil || len(ips) == 0 {
		fmt.Printf("\n %s[!] Error resolving hostname: %v%s\n", banner.Bold+banner.Red, err, banner.Reset)
		return
	}

	var cnamesAndPTRs []string
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil && cname != "" {
		cnamesAndPTRs = append(cnamesAndPTRs, strings.TrimSuffix(cname, "."))
	}
	for _, ip := range ips {
		if ptrs, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil {
			for _, ptr := range ptrs {
				cnamesAndPTRs = append(cnamesAndPTRs, strings.TrimSuffix(ptr, "."))
			}
		}
	}
	cancel()

	fmt.Printf("\n %s═══ 1. NETWORK & DNS INTELLIGENCE ═══%s\n", banner.Bold+banner.Cyan, banner.Reset)
	fmt.Printf("  %sResolved IPs (%d):%s\n", banner.Bold+banner.White, len(ips), banner.Reset)
	for _, ip := range ips {
		fmt.Printf("    • %s%s%s\n", banner.Green, ip, banner.Reset)
	}
	if len(cnamesAndPTRs) > 0 {
		fmt.Printf("  %sCNAME / Reverse PTR Records:%s\n", banner.Bold+banner.White, banner.Reset)
		for _, cp := range cnamesAndPTRs {
			fmt.Printf("    • %s%s%s\n", banner.Yellow, cp, banner.Reset)
		}
	}

	// 2. Test all selected HTTP methods (including QUERY, WebDAV, etc.) concurrently
	fmt.Printf("\n %s═══ 2. HTTP METHOD MATRIX (%d Methods Tested) ═══%s\n", banner.Bold+banner.Cyan, len(methods), banner.Reset)

	type methodResult struct {
		Idx     int
		Method  string
		Code    int
		Status  string
		Headers http.Header
		Err     string
	}

	results := make([]methodResult, len(methods))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	primaryIP := ips[0]
	useTLS := proto == "https" || config.StandardTLSPorts[port]

	ds := scanner.NewDirectScanner(&input.TargetSpec{Entries: []string{host}}, methods, []string{port}, false, 5, 1, "", "")

	var sampleHeaders http.Header
	var hdrMu sync.Mutex

	for idx, m := range methods {
		wg.Add(1)
		go func(i int, method string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			urlStr := fmt.Sprintf("%s://%s/", proto, net.JoinHostPort(host, port))
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
				DisableKeepAlives: true,
			}
			client := &http.Client{
				Transport: transport,
				Timeout:   5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			req, err := http.NewRequest(method, urlStr, nil)
			if err == nil {
				req.Header.Set("User-Agent", config.RandomUserAgent())
				if config.MethodNeedsContentLengthZero(method) {
					req.Header.Set("Content-Length", "0")
					req.ContentLength = 0
				}
				resp, err := client.Do(req)
				if err == nil {
					_ = resp.Body.Close()
					hdrMu.Lock()
					if sampleHeaders == nil || method == "GET" {
						sampleHeaders = resp.Header.Clone()
					}
					hdrMu.Unlock()
					results[i] = methodResult{
						Idx:     i,
						Method:  method,
						Code:    resp.StatusCode,
						Status:  resp.Status,
						Headers: resp.Header,
					}
					return
				}
			}

			// Fallback to DirectScanner's dual-engine (including Raw Wire socket probe for CONNECT/PRI/QUERY)
			_ = ds
			rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(primaryIP, port), 5*time.Second)
			if err != nil {
				results[i] = methodResult{Idx: i, Method: method, Err: err.Error()}
				return
			}
			_ = rawConn.Close()
			results[i] = methodResult{Idx: i, Method: method, Err: "Rejected or non-standard response"}
		}(idx, m)
	}
	wg.Wait()

	for _, r := range results {
		if r.Code > 0 {
			color := banner.Green
			if r.Code >= 300 && r.Code < 400 {
				color = banner.Yellow
			} else if r.Code >= 400 {
				color = banner.Cyan
			}
			loc := r.Headers.Get("Location")
			allow := r.Headers.Get("Allow")
			extra := ""
			if allow != "" {
				extra += fmt.Sprintf(" [Allow: %s]", allow)
			}
			if loc != "" {
				extra += fmt.Sprintf(" [Location: %s]", loc)
			}
			fmt.Printf("  %s%-12s%s │ %s%-28s%s │ Server: %s%s\n",
				banner.Bold+banner.Yellow, r.Method, banner.Reset,
				color, r.Status, banner.Reset,
				r.Headers.Get("Server"), extra)
		} else {
			fmt.Printf("  %s%-12s%s │ %sFailed (%s)%s\n",
				banner.Gray, r.Method, banner.Reset,
				banner.Red, r.Err, banner.Reset)
		}
	}

	if sampleHeaders != nil {
		fmt.Printf("\n  %sResponse Headers (Sample):%s\n", banner.Bold+banner.White, banner.Reset)
		var keys []string
		for k := range sampleHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("    %s%s:%s %s\n", banner.Cyan, k, banner.Reset, strings.Join(sampleHeaders[k], ", "))
		}
	}

	// 3. CDN Detection
	fmt.Printf("\n %s═══ 3. CDN / WAF DETECTION ═══%s\n", banner.Bold+banner.Cyan, banner.Reset)
	cdns := detectCDNs(sampleHeaders, cnamesAndPTRs)
	if len(cdns) > 0 {
		for _, c := range cdns {
			fmt.Printf("    • %s%s%s\n", banner.Bold+banner.Green, c, banner.Reset)
		}
	} else {
		fmt.Printf("    • %sNo known CDN signature detected (Direct Origin or Custom Proxy)%s\n", banner.Yellow, banner.Reset)
	}

	// 4. SSL / TLS & SAN Certificate Analysis
	if useTLS {
		fmt.Printf("\n %s═══ 4. SSL / TLS & SAN CERTIFICATE ANALYSIS ═══%s\n", banner.Bold+banner.Cyan, banner.Reset)
		rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(primaryIP, port), 5*time.Second)
		if err != nil {
			fmt.Printf("    %s[!] TCP Connect failed on port %s: %v%s\n", banner.Red, port, err, banner.Reset)
			return
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err := tlsConn.Handshake(); err != nil {
			fmt.Printf("    %s[!] TLS Handshake failed: %v%s\n", banner.Red, err, banner.Reset)
			return
		}
		state := tlsConn.ConnectionState()
		fmt.Printf("    %sSSL/TLS Version:%s %s\n", banner.Bold+banner.White, banner.Reset, tls.VersionName(state.Version))
		fmt.Printf("    %sCipher Suite:%s    %s\n", banner.Bold+banner.White, banner.Reset, tls.CipherSuiteName(state.CipherSuite))
		fmt.Printf("    %sALPN Protocol:%s   %s\n", banner.Bold+banner.White, banner.Reset, state.NegotiatedProtocol)

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			fmt.Printf("    %sSubject:%s         %s\n", banner.Bold+banner.White, banner.Reset, cert.Subject.String())
			fmt.Printf("    %sIssuer:%s          %s\n", banner.Bold+banner.White, banner.Reset, cert.Issuer.String())
			fmt.Printf("    %sSerial Number:%s   %s\n", banner.Bold+banner.White, banner.Reset, cert.SerialNumber.String())
			fmt.Printf("    %sValid From/To:%s   %s -> %s\n", banner.Bold+banner.White, banner.Reset,
				cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
			if len(cert.DNSNames) > 0 {
				maxSAN := len(cert.DNSNames)
				if maxSAN > 15 {
					fmt.Printf("    %sSAN Domains (%d total, showing 15):%s %s ...\n",
						banner.Bold+banner.Green, len(cert.DNSNames), banner.Reset, strings.Join(cert.DNSNames[:15], ", "))
				} else {
					fmt.Printf("    %sSAN Domains (%d):%s %s\n",
						banner.Bold+banner.Green, len(cert.DNSNames), banner.Reset, strings.Join(cert.DNSNames, ", "))
				}
			}
		}
	}
}
