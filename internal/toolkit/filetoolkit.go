package toolkit

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

var (
	// Supports modern TLDs up to 63 chars (fixes Python's {2,6} truncation bug!)
	cleanDomainRegex = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	cleanIPv4Regex   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

func readLines(path string) ([]string, error) {
	path = strings.Trim(path, "\"'")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func writeLines(path string, lines []string) error {
	path = strings.Trim(path, "\"'")
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	bw := bufio.NewWriterSize(f, 64*1024)
	for _, l := range lines {
		_, _ = bw.WriteString(l + "\n")
	}
	return bw.Flush()
}

func splitFile() {
	fp := banner.PromptText("Enter file path to split", "", true)
	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error or empty file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}
	parts := banner.PromptInt("Number of parts", 2, 1)
	if parts > len(lines) {
		parts = len(lines)
	}

	perFile := len(lines) / parts
	ext := filepath.Ext(fp)
	base := strings.TrimSuffix(fp, ext)

	fmt.Printf("\n %sFILE SPLIT RESULTS:%s\n", banner.Bold+banner.Cyan, banner.Reset)
	for i := 0; i < parts; i++ {
		start := i * perFile
		end := (i + 1) * perFile
		if i == parts-1 {
			end = len(lines)
		}
		partPath := fmt.Sprintf("%s_part_%d.txt", base, i+1)
		chunk := lines[start:end]
		if err := writeLines(partPath, chunk); err == nil {
			fmt.Printf("  %s• %s: %d lines%s\n", banner.Green, filepath.Base(partPath), len(chunk), banner.Reset)
		}
	}
}

func mergeFiles() {
	cwd, _ := os.Getwd()
	dir := banner.PromptText("Enter directory path", cwd, true)
	mergeAll := banner.PromptConfirm("Merge all .txt files in directory?", true)

	var files []string
	if mergeAll {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf(" %s[!] Error reading directory: %v%s\n", banner.Red, err, banner.Reset)
			return
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
				files = append(files, e.Name())
			}
		}
	} else {
		raw := banner.PromptText("Enter filenames (comma-separated)", "", true)
		for _, p := range strings.Split(raw, ",") {
			if s := strings.TrimSpace(p); s != "" {
				files = append(files, s)
			}
		}
	}

	if len(files) == 0 {
		fmt.Printf(" %s[!] No .txt files found to merge.%s\n", banner.Red, banner.Reset)
		return
	}

	outName := banner.PromptText("Enter output filename", "merged.txt", true)
	outPath := filepath.Join(dir, outName)

	var allLines []string
	mergedCount := 0
	for _, fn := range files {
		if strings.EqualFold(fn, outName) {
			continue // Don't merge the output file into itself!
		}
		fullPath := filepath.Join(dir, fn)
		if lines, err := readLines(fullPath); err == nil {
			allLines = append(allLines, lines...)
			mergedCount++
		}
	}

	if err := writeLines(outPath, allLines); err == nil {
		fmt.Printf("\n %s[✓] Merged %d files (%d total lines) into '%s'%s\n",
			banner.Bold+banner.Green, mergedCount, len(allLines), outPath, banner.Reset)
	}
}

func cleanFile() {
	fp := banner.PromptText("Enter messy input file path", "", true)
	domOut := banner.PromptText("Enter domains output filename", "cleaned_domains.txt", true)
	ipOut := banner.PromptText("Enter IPs output filename", "cleaned_ips.txt", true)

	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}

	joined := strings.Join(lines, "\n")
	domSet := make(map[string]bool)
	for _, m := range cleanDomainRegex.FindAllString(joined, -1) {
		domSet[strings.ToLower(m)] = true
	}

	ipSet := make(map[string]bool)
	for _, m := range cleanIPv4Regex.FindAllString(joined, -1) {
		if addr, err := netip.ParseAddr(m); err == nil {
			ipSet[addr.String()] = true
		}
	}

	var doms, ips []string
	for d := range domSet {
		doms = append(doms, d)
	}
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(doms)
	sort.Strings(ips)

	_ = writeLines(domOut, doms)
	_ = writeLines(ipOut, ips)

	fmt.Printf("\n %sFILE CLEANER RESULTS:%s\n", banner.Bold+banner.Cyan, banner.Reset)
	fmt.Printf("  %s• Extracted %d unique valid domains -> %s%s\n", banner.Green, len(doms), domOut, banner.Reset)
	fmt.Printf("  %s• Extracted %d unique valid IPs     -> %s%s\n", banner.Green, len(ips), ipOut, banner.Reset)
}

func deduplicateFile() {
	fp := banner.PromptText("Enter file path to deduplicate", "", true)
	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}

	seen := make(map[string]bool, len(lines))
	var unique []string
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			unique = append(unique, l)
		}
	}
	sort.Strings(unique)

	if err := writeLines(fp, unique); err == nil {
		fmt.Printf("\n %sDEDUPLICATION RESULTS:%s\n", banner.Bold+banner.Cyan, banner.Reset)
		fmt.Printf("  %s• Original lines:     %d%s\n", banner.Green, len(lines), banner.Reset)
		fmt.Printf("  %s• Unique lines:       %d%s\n", banner.Green, len(unique), banner.Reset)
		fmt.Printf("  %s• Duplicates removed: %d%s\n", banner.Yellow, len(lines)-len(unique), banner.Reset)
	}
}

func filterByTLD() {
	fp := banner.PromptText("Enter domains file path", "", true)
	tldsRaw := banner.PromptText("Enter TLDs (e.g. com, org, net, or 'all')", "all", true)

	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}

	tldMap := make(map[string][]string)
	for _, d := range lines {
		clean := input.NormalizeHost(d)
		parts := strings.Split(clean, ".")
		if len(parts) > 1 {
			tld := strings.ToLower(parts[len(parts)-1])
			tldMap[tld] = append(tldMap[tld], clean)
		}
	}

	ext := filepath.Ext(fp)
	base := strings.TrimSuffix(fp, ext)

	var targetTLDs []string
	if strings.EqualFold(strings.TrimSpace(tldsRaw), "all") {
		for k := range tldMap {
			targetTLDs = append(targetTLDs, k)
		}
		sort.Strings(targetTLDs)
	} else {
		for _, p := range strings.Split(tldsRaw, ",") {
			t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(p)), ".")
			if t != "" {
				targetTLDs = append(targetTLDs, t)
			}
		}
	}

	fmt.Printf("\n %sTLD FILTER RESULTS:%s\n", banner.Bold+banner.Cyan, banner.Reset)
	for _, tld := range targetTLDs {
		list := tldMap[tld]
		if len(list) == 0 {
			fmt.Printf("  %s• No domains found with .%s%s\n", banner.Yellow, tld, banner.Reset)
			continue
		}
		sort.Strings(list)
		outFile := fmt.Sprintf("%s_%s.txt", base, tld)
		if err := writeLines(outFile, list); err == nil {
			fmt.Printf("  %s• Created '%s' with %d domains%s\n", banner.Green, filepath.Base(outFile), len(list), banner.Reset)
		}
	}
}

func filterByKeyword() {
	fp := banner.PromptText("Enter file path", "", true)
	kwRaw := banner.PromptText("Enter keyword(s) (comma-separated)", "", true)
	outFile := banner.PromptText("Enter output filename", "filtered_keywords.txt", true)

	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}

	var kws []string
	for _, k := range strings.Split(kwRaw, ",") {
		if s := strings.ToLower(strings.TrimSpace(k)); s != "" {
			kws = append(kws, s)
		}
	}

	var matched []string
	for _, l := range lines {
		ll := strings.ToLower(l)
		for _, kw := range kws {
			if strings.Contains(ll, kw) {
				matched = append(matched, l)
				break
			}
		}
	}

	if err := writeLines(outFile, matched); err == nil {
		fmt.Printf("\n %s[✓] Matched %d / %d lines -> saved to '%s'%s\n",
			banner.Bold+banner.Green, len(matched), len(lines), outFile, banner.Reset)
	}
}

func cidrToIP() {
	cidrRaw := banner.PromptText("Enter CIDR range(s) or IP range (comma-separated)", "", true)
	outFile := banner.PromptText("Enter output filename", "cidr_ips.txt", true)

	var entries []string
	for _, p := range strings.Split(cidrRaw, ",") {
		if s := strings.TrimSpace(p); s != "" {
			entries = append(entries, s)
		}
	}
	spec := &input.TargetSpec{Entries: entries}

	f, err := os.Create(outFile)
	if err != nil {
		fmt.Printf(" %s[!] Failed to create output file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 64*1024)

	var count int64
	spec.StreamTargets(func(ip string) bool {
		_, _ = bw.WriteString(ip + "\n")
		count++
		return true
	})
	_ = bw.Flush()

	fmt.Printf("\n %s[✓] Expanded %d IP addresses to '%s'%s\n",
		banner.Bold+banner.Green, count, outFile, banner.Reset)
}

// domainsToIP fixes Python's broken validators="cidr" bug and resolves domains concurrently with fallback DNS!
func domainsToIP() {
	fp := banner.PromptText("Enter domains file path", "", true)
	outFile := banner.PromptText("Enter output IP filename", "resolved_ips.txt", true)

	lines, err := readLines(fp)
	if err != nil || len(lines) == 0 {
		fmt.Printf(" %s[!] Error reading file: %v%s\n", banner.Red, err, banner.Reset)
		return
	}

	workers := banner.PromptInt("Enter concurrent DNS workers", 150, 1)

	var ipMu sync.Mutex
	ipSet := make(map[string]bool)
	var resolvedCount atomic.Int64
	var failedCount atomic.Int64
	var processed atomic.Int64
	total := int64(len(lines))

	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h\n")

	domChan := make(chan string, workers*2)
	var wg sync.WaitGroup
	startTime := time.Now()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawDom := range domChan {
				dom := input.NormalizeHost(rawDom)
				if dom == "" {
					processed.Add(1)
					continue
				}
				ips, err := resolver.Default.ResolveAll(dom)
				if err == nil && len(ips) > 0 {
					resolvedCount.Add(1)
					ipMu.Lock()
					for _, ip := range ips {
						ipSet[ip] = true
					}
					ipMu.Unlock()
				} else {
					failedCount.Add(1)
				}
				done := processed.Add(1)
				if done%25 == 0 || done == total {
					fmt.Printf("\r\033[2K %sResolving: %d / %d | Resolved: %d | Failed: %d%s",
						banner.Yellow, done, total, resolvedCount.Load(), failedCount.Load(), banner.Reset)
				}
			}
		}()
	}

	for _, l := range lines {
		domChan <- l
	}
	close(domChan)
	wg.Wait()

	var sortedIPs []string
	for ip := range ipSet {
		sortedIPs = append(sortedIPs, ip)
	}
	sort.Strings(sortedIPs)

	if len(sortedIPs) > 0 {
		_ = writeLines(outFile, sortedIPs)
	}

	fmt.Printf("\n\n %sDOMAIN RESOLUTION RESULTS (%s):%s\n", banner.Bold+banner.Cyan, time.Since(startTime).Round(time.Millisecond), banner.Reset)
	fmt.Printf("  %s• Input domains:         %d%s\n", banner.White, total, banner.Reset)
	fmt.Printf("  %s• Successfully resolved: %d%s\n", banner.Green, resolvedCount.Load(), banner.Reset)
	fmt.Printf("  %s• Failed to resolve:     %d%s\n", banner.Yellow, failedCount.Load(), banner.Reset)
	fmt.Printf("  %s• Unique IP addresses:   %d -> saved to '%s'%s\n", banner.Bold+banner.Green, len(sortedIPs), outFile, banner.Reset)
}

func RunInteractiveFileToolkit() {
	for {
		banner.PrintSectionTitle("FILE TOOLKIT")
		options := []struct {
			Key   string
			Label string
			Color string
			Fn    func()
		}{
			{"1", "SPLIT FILE", banner.Bold + banner.Cyan, splitFile},
			{"2", "MERGE FILES", banner.Bold + banner.Blue, mergeFiles},
			{"3", "CLEAN FILE (Extract Domains & IPs)", banner.Bold + banner.Cyan, cleanFile},
			{"4", "DEDUPLICATE & SORT", banner.Bold + banner.Yellow, deduplicateFile},
			{"5", "FILTER BY TLD", banner.Bold + banner.Magenta, filterByTLD},
			{"6", "FILTER BY KEYWORD", banner.Bold + banner.Yellow, filterByKeyword},
			{"7", "CIDR TO IP EXPANDER", banner.Bold + banner.Green, cidrToIP},
			{"8", "DOMAIN TO IP RESOLVER (Multi-DNS)", banner.Bold + banner.Blue, domainsToIP},
			{"0", "BACK TO MAIN MENU", banner.Bold + banner.Red, nil},
		}

		for _, opt := range options {
			fmt.Printf("  %s[%s] %s%s\n", opt.Color, opt.Key, opt.Label, banner.Reset)
		}

		choice := banner.PromptText("Your Choice", "0", true)
		if choice == "0" {
			return
		}

		for _, opt := range options {
			if opt.Key == choice && opt.Fn != nil {
				banner.PrintSectionTitle(opt.Label)
				opt.Fn()
				fmt.Printf("\n %sPress Enter to continue...%s", banner.Yellow, banner.Reset)
				banner.ReadLine()
				break
			}
		}
	}
}
