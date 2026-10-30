package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
)

var (
	tdDomainRegex   = regexp.MustCompile(`(?i)<td>([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)</td>`)
	totalSpanRegex  = regexp.MustCompile(`color:\s*#39cfca;\s*">(\d+)</span>`)
)

func fetchRapidDNSSameIP(client *http.Client, ip string) []string {
	var out []string
	body, err := fetchBody(client, fmt.Sprintf("https://rapiddns.io/sameip/%s", ip))
	if err != nil {
		return nil
	}
	html := string(body)
	for _, m := range tdDomainRegex.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			out = append(out, strings.ToLower(strings.TrimSpace(m[1])))
		}
	}

	if sm := totalSpanRegex.FindStringSubmatch(html); len(sm) > 1 {
		if total, err := strconv.Atoi(sm[1]); err == nil && total > 100 {
			pages := (total + 99) / 100
			if pages > 15 {
				pages = 15
			}
			for page := 2; page <= pages; page++ {
				pBody, err := fetchBody(client, fmt.Sprintf("https://rapiddns.io/sameip/%s?page=%d", ip, page))
				if err != nil {
					continue
				}
				for _, m := range tdDomainRegex.FindAllStringSubmatch(string(pBody), -1) {
					if len(m) > 1 {
						out = append(out, strings.ToLower(strings.TrimSpace(m[1])))
					}
				}
			}
		}
	}
	return out
}

func fetchYouGetSignal(client *http.Client, ip string) []string {
	form := url.Values{}
	form.Set("remoteAddress", ip)
	form.Set("key", "")
	form.Set("_", "")

	req, err := http.NewRequest("POST", "https://domains.yougetsignal.com/domains.php", strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", config.RandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}
	var parsed struct {
		DomainArray [][]string `json:"domainArray"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var out []string
	for _, pair := range parsed.DomainArray {
		if len(pair) > 0 && pair[0] != "" {
			out = append(out, strings.ToLower(strings.TrimSpace(pair[0])))
		}
	}
	return out
}

func fetchHackerTargetReverseIP(client *http.Client, ip string) []string {
	body, err := fetchBody(client, fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip))
	if err != nil {
		return nil
	}
	text := string(body)
	if strings.Contains(strings.ToLower(text), "error") || strings.Contains(strings.ToLower(text), "no dns") || strings.Contains(strings.ToLower(text), "api count") {
		return nil
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		d := strings.ToLower(strings.TrimSpace(line))
		if d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, " \t/\\:") {
			out = append(out, d)
		}
	}
	return out
}

func fetchPTRRecord(ip string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func RunIPLookup(spec *input.TargetSpec, outputFile string) []string {
	total := spec.CountTargets()
	if total == 0 {
		fmt.Printf(" %s[!] No valid IPs or CIDRs provided.%s\n", banner.Red, banner.Reset)
		return nil
	}

	if dir := filepath.Dir(outputFile); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	client := newScraperHTTPClient(12 * time.Second)
	var globalMu sync.Mutex
	globalDomains := make(map[string]bool)
	var completed atomic.Int64

	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h\n")

	ipChan := make(chan string, 100)
	var wg sync.WaitGroup

	workers := 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				var srcWg sync.WaitGroup
				var ipMu sync.Mutex
				ipSet := make(map[string]bool)

				addDomains := func(list []string) {
					ipMu.Lock()
					for _, d := range list {
						if d != "" && strings.Contains(d, ".") {
							ipSet[d] = true
						}
					}
					ipMu.Unlock()
				}

				srcWg.Add(4)
				go func() { defer srcWg.Done(); addDomains(fetchRapidDNSSameIP(client, ip)) }()
				go func() { defer srcWg.Done(); addDomains(fetchYouGetSignal(client, ip)) }()
				go func() { defer srcWg.Done(); addDomains(fetchHackerTargetReverseIP(client, ip)) }()
				go func() { defer srcWg.Done(); addDomains(fetchPTRRecord(ip)) }()
				srcWg.Wait()

				globalMu.Lock()
				for d := range ipSet {
					globalDomains[d] = true
				}
				globalMu.Unlock()

				done := completed.Add(1)
				if len(ipSet) > 0 {
					fmt.Printf("\r\033[2K %s[✓] %s: %d domains found%s\n", banner.Green, ip, len(ipSet), banner.Reset)
				}
				fmt.Printf("\r\033[2K %sProgress: %d / %d IPs | Unique Domains: %d%s",
					banner.Cyan, done, total, len(globalDomains), banner.Reset)
			}
		}()
	}

	spec.StreamTargets(func(target string) bool {
		ipChan <- target
		return true
	})
	close(ipChan)
	wg.Wait()

	var sorted []string
	for d := range globalDomains {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)

	if len(sorted) > 0 && outputFile != "" {
		// Deduplicated write (fixes Python's test_iplookup duplicate append bug!)
		_ = os.WriteFile(outputFile, []byte(strings.Join(sorted, "\n")+"\n"), 0644)
	}

	fmt.Printf("\n\n %s[✓] Total Unique Domains Found: %d%s\n", banner.Bold+banner.Green, len(sorted), banner.Reset)
	if outputFile != "" {
		fmt.Printf(" %s[✓] Saved to: %s%s\n", banner.Cyan, outputFile, banner.Reset)
	}
	return sorted
}

func RunInteractiveIPLookup() {
	spec, err := input.PromptTargetSpec()
	if err != nil || spec == nil {
		return
	}
	outFile := banner.PromptText("Enter output filename", "reverse_domains.txt", true)
	fmt.Println()
	RunIPLookup(spec, outFile)
}
