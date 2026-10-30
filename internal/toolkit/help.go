package toolkit

import (
	"fmt"
	"strings"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
)

func RunInteractiveHelp() {
	fmt.Printf(`
 %s╔══════════════════════════════════════════════════════════════════════════╗
 ║               BUGSCANX-GO v%s — COMPLETE FEATURE GUIDE              ║
 ╚══════════════════════════════════════════════════════════════════════════╝%s

 %s1. ZERO-FALSE-NEGATIVE SCANNING ENGINE (NEVER SKIPS WORKING HOSTS):%s
    • %sMulti-DNS Fallback Resolver:%s Queries OS DNS -> Cloudflare (1.1.1.1) ->
      Google (8.8.8.8) -> Quad9 (9.9.9.9) over both UDP and TCP so UDP packet
      drops never cause a working domain to be skipped.
    • %sMulti-IP Failover:%s If a host has multiple A/AAAA records and the first IP
      times out, BugScanX-Go automatically tests the backup IPs.
    • %sSmart HTTP <-> HTTPS Auto-Switch:%s Automatically detects TLS on non-standard
      ports (e.g. 8443, 2053, 2083, 2087, 2096) or when a port returns a 400 HTTPS
      error or raw TLS alert, seamlessly retrying with the matching protocol.
    • %sRaw Wire Socket Fallback:%s If Go's standard HTTP parser rejects a non-RFC
      server response or custom method, it falls back to a raw TCP/TLS wire probe.
    • %sFixed WebSocket 101 Detection:%s Reads HTTP headers up to \r\n\r\n immediately
      without blocking until socket EOF, capturing 100%% of 101 Switching Protocols hosts.

 %s2. ALL SUPPORTED HTTP + MODERN + WEBDAV METHODS (35 BUILT-IN + CUSTOM):%s
    • %sCore RFC 9110:%s  %s
    • %sNewer IETF:%s     QUERY (Safe/Idempotent Query), PRI (HTTP/2 Preface)
    • %sExtended/Bypass:%s %s

 %s3. CLI AUTOMATION FLAGS (OPTIONAL):%s
    You can launch interactively (no flags) OR use CLI flags directly:
      %sbugscanx-go -mode direct -target example.com,104.16.0.0/24 -ports 80,443 -methods all -workers 200 -out hits.txt%s
      %sbugscanx-go -mode no302 -file hosts.txt -ports 80,443,8443 -methods bypass -sni zero.isp.com%s
      %sbugscanx-go -mode proxytest -file hosts.txt -target ws.tunnel.site -ports 80,443%s
`,
		banner.Bold+banner.Cyan, config.Version, banner.Reset,
		banner.Bold+banner.Green, banner.Reset,
		banner.Yellow, banner.Reset,
		banner.Yellow, banner.Reset,
		banner.Yellow, banner.Reset,
		banner.Yellow, banner.Reset,
		banner.Yellow, banner.Reset,
		banner.Bold+banner.Magenta, banner.Reset,
		banner.Cyan, banner.Reset, strings.Join(config.StandardMethods, ", "),
		banner.Cyan, banner.Reset,
		banner.Cyan, banner.Reset, strings.Join(config.AllExtendedMethods[11:], ", "),
		banner.Bold+banner.Yellow, banner.Reset,
		banner.Green, banner.Reset,
		banner.Green, banner.Reset,
		banner.Green, banner.Reset,
	)
}
