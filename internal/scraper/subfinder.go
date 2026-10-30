package scraper

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
)

type SubdomainSourceFunc func(client *http.Client, domain string) []string

type SubSource struct {
	Name string
	Fn   SubdomainSourceFunc
}

func newScraperHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func fetchBody(client *http.Client, urlStr string) ([]byte, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", config.RandomUserAgent())
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 15*1024*1024))
}

func getSubdomainSources() []SubSource {
	return []SubSource{
		{
			Name: "Crt.sh",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
				if err != nil {
					return nil
				}
				var entries []struct {
					NameValue string `json:"name_value"`
				}
				if err := json.Unmarshal(body, &entries); err != nil {
					return nil
				}
				var out []string
				for _, e := range entries {
					for _, line := range strings.Split(e.NameValue, "\n") {
						out = append(out, line)
					}
				}
				return out
			},
		},
		{
			Name: "HackerTarget",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
				if err != nil {
					return nil
				}
				var out []string
				for _, line := range strings.Split(string(body), "\n") {
					parts := strings.SplitN(line, ",", 2)
					if len(parts) > 0 {
						out = append(out, parts[0])
					}
				}
				return out
			},
		},
		{
			Name: "RapidDNS",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
				if err != nil {
					return nil
				}
				return extractMatchingSubdomains(string(body), domain)
			},
		},
		{
			Name: "AnubisDB",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain))
				if err != nil {
					return nil
				}
				var list []string
				_ = json.Unmarshal(body, &list)
				return list
			},
		},
		{
			Name: "AlienVault OTX",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
				if err != nil {
					return nil
				}
				var data struct {
					PassiveDNS []struct {
						Hostname string `json:"hostname"`
					} `json:"passive_dns"`
				}
				if err := json.Unmarshal(body, &data); err != nil {
					return nil
				}
				var out []string
				for _, item := range data.PassiveDNS {
					out = append(out, item.Hostname)
				}
				return out
			},
		},
		{
			Name: "CertSpotter",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain))
				if err != nil {
					return nil
				}
				var certs []struct {
					DNSNames []string `json:"dns_names"`
				}
				if err := json.Unmarshal(body, &certs); err != nil {
					return nil
				}
				var out []string
				for _, c := range certs {
					out = append(out, c.DNSNames...)
				}
				return out
			},
		},
		{
			Name: "URLScan.io",
			Fn: func(client *http.Client, domain string) []string {
				body, err := fetchBody(client, fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=1000", domain))
				if err != nil {
					return nil
				}
				return extractMatchingSubdomains(string(body), domain)
			},
		},
	}
}

func extractMatchingSubdomains(text, rootDomain string) []string {
	escaped := regexp.QuoteMeta(rootDomain)
	re, err := regexp.Compile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` + escaped)
	if err != nil {
		return nil
	}
	return re.FindAllString(text, -1)
}

func cleanAndValidateSubdomain(raw, rootDomain string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}
	s = strings.TrimSuffix(s, ".")
	root := strings.ToLower(strings.TrimSpace(rootDomain))
	if s == root || strings.HasSuffix(s, "."+root) {
		if !strings.ContainsAny(s, " \t/\\:@") {
			return s
		}
	}
	return ""
}

func RunSubfinder(domains []string, outputFile string) []string {
	if len(domains) == 0 {
		fmt.Printf(" %s[!] No valid domains provided.%s\n", banner.Red, banner.Reset)
		return nil
	}

	if dir := filepath.Dir(outputFile); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	sources := getSubdomainSources()
	client := newScraperHTTPClient(15 * time.Second)

	var globalMu sync.Mutex
	globalSet := make(map[string]bool)
	var completed atomic.Int64
	total := int64(len(domains))

	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h\n")

	sem := make(chan struct{}, 4) // Process up to 4 root domains concurrently
	var wg sync.WaitGroup

	for _, dom := range domains {
		domain := input.NormalizeHost(dom)
		if domain == "" {
			completed.Add(1)
			continue
		}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("\r\033[2K %s[*] Enumerating subdomains for: %s%s\n", banner.Cyan, d, banner.Reset)

			var srcWg sync.WaitGroup
			var domMu sync.Mutex
			domSet := make(map[string]bool)

			for _, src := range sources {
				srcWg.Add(1)
				go func(s SubSource) {
					defer srcWg.Done()
					found := s.Fn(client, d)
					domMu.Lock()
					for _, rawSub := range found {
						if clean := cleanAndValidateSubdomain(rawSub, d); clean != "" {
							domSet[clean] = true
						}
					}
					domMu.Unlock()
				}(src)
			}
			srcWg.Wait()

			globalMu.Lock()
			for sub := range domSet {
				globalSet[sub] = true
			}
			globalMu.Unlock()

			done := completed.Add(1)
			fmt.Printf("\r\033[2K %s[✓] %s: %d unique subdomains found%s (Progress: %d/%d)\n",
				banner.Green, d, len(domSet), banner.Reset, done, total)
		}(domain)
	}

	wg.Wait()

	var allSorted []string
	for sub := range globalSet {
		allSorted = append(allSorted, sub)
	}
	sort.Strings(allSorted)

	if len(allSorted) > 0 && outputFile != "" {
		_ = os.WriteFile(outputFile, []byte(strings.Join(allSorted, "\n")+"\n"), 0644)
	}

	fmt.Printf("\n %s[✓] Total Unique Subdomains Found: %d%s\n", banner.Bold+banner.Green, len(allSorted), banner.Reset)
	if outputFile != "" {
		fmt.Printf(" %s[✓] Saved to: %s%s\n", banner.Cyan, outputFile, banner.Reset)
	}
	return allSorted
}

func RunInteractiveSubfinder() {
	modes := []string{"Manual Domain Input (comma-separated)", "File Input (TXT file with domains)"}
	mode := banner.PromptChoice("Select Subfinder Input Mode", modes, 0)

	var domains []string
	defaultOut := "subdomains.txt"

	if strings.HasPrefix(mode, "Manual") {
		raw := banner.PromptText("Enter domain(s) (comma-separated)", "", true)
		for _, part := range strings.Split(raw, ",") {
			if d := input.NormalizeHost(part); d != "" {
				domains = append(domains, d)
			}
		}
		if len(domains) > 0 {
			defaultOut = domains[0] + "_subdomains.txt"
		}
	} else {
		fp := banner.PromptText("Enter domains file path", "", true)
		fp = strings.Trim(fp, "\"'")
		data, err := os.ReadFile(fp)
		if err != nil {
			fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if d := input.NormalizeHost(line); d != "" {
				domains = append(domains, d)
			}
		}
		ext := filepath.Ext(fp)
		defaultOut = strings.TrimSuffix(fp, ext) + "_subdomains.txt"
	}

	outFile := banner.PromptText("Enter output filename", defaultOut, true)
	fmt.Println()
	RunSubfinder(domains, outFile)
}
