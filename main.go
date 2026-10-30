package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/scanner"
	"github.com/FreeNetLabs/bugscanx-go/internal/scraper"
	"github.com/FreeNetLabs/bugscanx-go/internal/toolkit"
)

func main() {
	// Optional CLI flags for non-interactive / scripted runs
	modeFlag := flag.String("mode", "", "Scan mode: direct, no302, proxytest, ssl, ping, subfinder, iplookup")
	fileFlag := flag.String("file", "", "Input file path (hosts, IPs, or CIDRs)")
	targetFlag := flag.String("target", "", "Comma-separated hosts, IPs, CIDRs, or start-end ranges")
	portsFlag := flag.String("ports", "80,443", "Comma-separated ports or ranges (e.g. 80,443,8080-8090)")
	methodsFlag := flag.String("methods", "bypass", "HTTP methods: 'bypass' (17), 'all' (35), 'standard' (9), or comma-separated (e.g. GET,HEAD,QUERY,PROPFIND)")
	workersFlag := flag.Int("workers", 150, "Number of concurrent goroutines")
	timeoutFlag := flag.Int("timeout", 4, "Timeout in seconds per attempt")
	retriesFlag := flag.Int("retries", 2, "Retries on timeout to avoid skipping slow hosts")
	hostHdrFlag := flag.String("host", "", "Optional spoofed HTTP Host header or WebSocket target")
	sniFlag := flag.String("sni", "", "Optional spoofed TLS SNI hostname")
	payloadFlag := flag.String("payload", "", "Custom payload for proxytest mode")
	outFlag := flag.String("out", "results.txt", "Output file path")
	flag.Parse()

	if *modeFlag != "" {
		runCLIMode(*modeFlag, *fileFlag, *targetFlag, *portsFlag, *methodsFlag, *workersFlag, *timeoutFlag, *retriesFlag, *hostHdrFlag, *sniFlag, *payloadFlag, *outFlag)
		return
	}

	runInteractiveMenu()
}

func resolveMethodsFlag(raw string) []string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "bypass", "modern":
		return append([]string{}, config.ModernAndBypassMethods...)
	case "all", "extended":
		return append([]string{}, config.AllExtendedMethods...)
	case "standard", "std":
		return append([]string{}, config.StandardMethods...)
	default:
		var out []string
		for _, p := range strings.Split(raw, ",") {
			if m := strings.ToUpper(strings.TrimSpace(p)); m != "" {
				out = append(out, m)
			}
		}
		if len(out) == 0 {
			return []string{"GET"}
		}
		return out
	}
}

func runCLIMode(mode, filePath, targetsRaw, portsRaw, methodsRaw string, workers, timeout, retries int, customHost, customSNI, payload, outFile string) {
	banner.PrintBanner()
	spec := &input.TargetSpec{
		FilePath: filePath,
	}
	if targetsRaw != "" {
		for _, p := range strings.Split(targetsRaw, ",") {
			if s := strings.TrimSpace(p); s != "" {
				spec.Entries = append(spec.Entries, s)
			}
		}
	}
	spec.Description = fmt.Sprintf("File:%s Targets:%s", filePath, targetsRaw)

	ports := input.ParsePorts(portsRaw)
	methods := resolveMethodsFlag(methodsRaw)

	switch strings.ToLower(mode) {
	case "direct", "no302", "directnon302":
		no302 := strings.ToLower(mode) != "direct"
		runner := scanner.NewDirectScanner(spec, methods, ports, no302, timeout, retries, customHost, customSNI)
		eng := scanner.NewEngine(workers, outFile)
		eng.Run(runner)
	case "proxytest", "ws":
		wsTarget := customHost
		if wsTarget == "" {
			wsTarget = "in1.wstunnel.site"
		}
		runner := scanner.NewProxyCheckScanner(spec, ports, wsTarget, payload, timeout, retries)
		eng := scanner.NewEngine(workers, outFile)
		eng.Run(runner)
	case "ssl", "sni":
		runner := scanner.NewSSLScanner(spec, ports, customSNI, timeout, retries)
		eng := scanner.NewEngine(workers, outFile)
		eng.Run(runner)
	case "ping":
		runner := scanner.NewPingScanner(spec, ports, timeout, retries)
		eng := scanner.NewEngine(workers, outFile)
		eng.Run(runner)
	case "subfinder":
		var doms []string
		spec.StreamTargets(func(t string) bool {
			doms = append(doms, t)
			return true
		})
		scraper.RunSubfinder(doms, outFile)
	case "iplookup":
		scraper.RunIPLookup(spec, outFile)
	default:
		fmt.Printf(" %s[!] Unknown mode '%s'. Valid modes: direct, no302, proxytest, ssl, ping, subfinder, iplookup%s\n",
			banner.Red, mode, banner.Reset)
		os.Exit(1)
	}
}

func runInteractiveMenu() {
	menuOptions := []struct {
		Key   string
		Title string
		Color string
		Fn    func()
	}{
		{"1", "HOST SCANNER (All HTTP + QUERY + WebDAV Methods)", banner.Bold + banner.Cyan, scanner.RunInteractiveHostScanner},
		{"2", "SUBFINDER (7 Concurrent Passive Sources)", banner.Bold + banner.Magenta, scraper.RunInteractiveSubfinder},
		{"3", "IP LOOKUP (Reverse IP & CIDR Domain Discovery)", banner.Bold + banner.Cyan, scraper.RunInteractiveIPLookup},
		{"4", "FILE TOOLKIT (Split, Merge, Clean, Dedup, Resolve)", banner.Bold + banner.Magenta, toolkit.RunInteractiveFileToolkit},
		{"5", "PORT SCANNER (Common Tunneling & 1-65535 Ports)", banner.Bold + banner.White, scanner.RunInteractivePortScanner},
		{"6", "DNS RECORDS (A, AAAA, CNAME, MX, NS, TXT)", banner.Bold + banner.Green, toolkit.RunInteractiveDNSRecords},
		{"7", "HOST INFO (All IPs, CDN Prefix Match, SSL SANs, Method Matrix)", banner.Bold + banner.Blue, toolkit.RunInteractiveHostInfo},
		{"8", "HELP & CLI DOCUMENTATION", banner.Bold + banner.Yellow, toolkit.RunInteractiveHelp},
		{"0", "EXIT", banner.Bold + banner.Red, nil},
	}

	for {
		banner.PrintBanner()
		for _, opt := range menuOptions {
			fmt.Printf("  %s[%s]  %s%s\n", opt.Color, opt.Key, opt.Title, banner.Reset)
		}

		fmt.Printf("\n %s[-] Your Choice:%s ", banner.Cyan, banner.Reset)
		choice := banner.ReadLine()
		if choice == "0" || strings.EqualFold(choice, "exit") || strings.EqualFold(choice, "q") {
			fmt.Printf("\n %sGoodbye! Happy Bug Host Hunting!%s\n", banner.Bold+banner.Green, banner.Reset)
			return
		}

		for _, opt := range menuOptions {
			if opt.Key == choice && opt.Fn != nil {
				banner.PrintSectionTitle(opt.Title)
				opt.Fn()
				fmt.Printf("\n %sPress Enter to return to main menu...%s", banner.Yellow, banner.Reset)
				banner.ReadLine()
				break
			}
		}
	}
}
