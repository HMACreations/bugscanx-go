package input

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
)

// TargetSpec holds any combination of files, CIDRs, and direct hosts/IPs.
type TargetSpec struct {
	FilePath    string
	Entries     []string // Raw hosts, IPs, CIDRs, or start-end ranges
	Description string
}

// NormalizeHost cleans a raw line into a pure hostname or IP address without losing valid targets.
func NormalizeHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
		return ""
	}
	// Strip inline comments
	if idx := strings.Index(s, " #"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	// Strip wildcard prefix "*.example.com" -> "example.com" instead of dropping it!
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}
	if strings.HasPrefix(s, "*") {
		return ""
	}

	// If it contains a scheme (http://, https://, ws://, wss://), parse via url.Parse
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		} else {
			parts := strings.SplitN(s, "://", 2)
			if len(parts) == 2 {
				s = parts[1]
			}
		}
	}

	// Strip path, query, fragment
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		// Only strip '/' if it's NOT a valid CIDR prefix
		if _, err := netip.ParsePrefix(s); err != nil {
			s = s[:idx]
		}
	}

	// If host:port (and not unbracketed IPv6), strip the port so scanner can apply its port list
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	}

	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	return s
}

// CountPrefixHosts returns the exact number of target IPs in a CIDR prefix,
// properly handling /32 (1 IP), /31 (2 IPs), and standard subnets without returning 0!
func CountPrefixHosts(prefix netip.Prefix) int64 {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		hostBits := 32 - bits
		if hostBits <= 0 {
			return 1 // /32 single host
		}
		if hostBits == 1 {
			return 2 // /31 point-to-point RFC 3021 (both IPs are valid hosts)
		}
		total := int64(1) << hostBits
		return total - 2
	}
	// IPv6
	hostBits := 128 - bits
	if hostBits <= 0 {
		return 1
	}
	if hostBits > 20 {
		// Cap massive IPv6 prefix expansion to 1M unless specified
		return 1 << 20
	}
	return int64(1) << hostBits
}

// StreamPrefixIPs streams every IP in a CIDR prefix to the callback `emit`.
// Unlike Python's `network.hosts()`, this NEVER skips /32 or /31 prefixes!
func StreamPrefixIPs(prefix netip.Prefix, emit func(string) bool) {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		hostBits := 32 - bits
		if hostBits <= 0 {
			emit(addr.String())
			return
		}
		if hostBits == 1 {
			if !emit(addr.String()) {
				return
			}
			emit(addr.Next().String())
			return
		}
		// Standard subnet (/30 or larger): skip network (.0) and broadcast (.255)
		total := int64(1) << hostBits
		curr := addr.Next() // skip network address
		for i := int64(0); i < total-2; i++ {
			if !emit(curr.String()) {
				return
			}
			curr = curr.Next()
		}
		return
	}

	// IPv6
	count := CountPrefixHosts(prefix)
	curr := addr
	for i := int64(0); i < count; i++ {
		if !emit(curr.String()) {
			return
		}
		curr = curr.Next()
	}
}

// parseIPRange checks for "1.2.3.4-1.2.3.50" range syntax.
func parseIPRange(raw string) (netip.Addr, netip.Addr, int64, bool) {
	if !strings.Contains(raw, "-") {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	parts := strings.SplitN(raw, "-", 2)
	startAddr, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
	endAddr, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || !startAddr.Is4() || !endAddr.Is4() {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	s4 := startAddr.As4()
	e4 := endAddr.As4()
	sUint := uint32(s4[0])<<24 | uint32(s4[1])<<16 | uint32(s4[2])<<8 | uint32(s4[3])
	eUint := uint32(e4[0])<<24 | uint32(e4[1])<<16 | uint32(e4[2])<<8 | uint32(e4[3])
	if eUint < sUint {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	return startAddr, endAddr, int64(eUint-sUint) + 1, true
}

func countEntryTargets(raw string) int64 {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
		return 0
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return CountPrefixHosts(p)
	}
	if _, _, count, ok := parseIPRange(s); ok {
		return count
	}
	h := NormalizeHost(s)
	if h == "" {
		return 0
	}
	return 1
}

func streamEntryTargets(raw string, emit func(string) bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
		return
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		StreamPrefixIPs(p, emit)
		return
	}
	if startAddr, _, count, ok := parseIPRange(s); ok {
		curr := startAddr
		for i := int64(0); i < count; i++ {
			if !emit(curr.String()) {
				return
			}
			curr = curr.Next()
		}
		return
	}
	h := NormalizeHost(s)
	if h != "" {
		emit(h)
	}
}

// CountTargets accurately counts all expanded targets (unlike Python's raw '\n' byte counter).
func (ts *TargetSpec) CountTargets() int64 {
	var total int64
	for _, entry := range ts.Entries {
		total += countEntryTargets(entry)
	}
	if ts.FilePath != "" {
		f, err := os.Open(ts.FilePath)
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			buf := make([]byte, 0, 1024*1024)
			sc.Buffer(buf, 10*1024*1024)
			for sc.Scan() {
				for _, part := range strings.Split(sc.Text(), ",") {
					total += countEntryTargets(part)
				}
			}
		}
	}
	return total
}

// StreamTargets streams every single host/IP from Entries and FilePath without loading millions of CIDR IPs into RAM.
func (ts *TargetSpec) StreamTargets(emit func(target string) bool) {
	for _, entry := range ts.Entries {
		stop := false
		streamEntryTargets(entry, func(t string) bool {
			if !emit(t) {
				stop = true
				return false
			}
			return true
		})
		if stop {
			return
		}
	}

	if ts.FilePath != "" {
		f, err := os.Open(ts.FilePath)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		buf := make([]byte, 0, 1024*1024)
		sc.Buffer(buf, 10*1024*1024)
		for sc.Scan() {
			for _, part := range strings.Split(sc.Text(), ",") {
				stop := false
				streamEntryTargets(part, func(t string) bool {
					if !emit(t) {
						stop = true
						return false
					}
					return true
				})
				if stop {
					return
				}
			}
		}
	}
}

// ParsePorts parses comma-separated ports and port ranges (e.g., "80,443,8080-8090").
func ParsePorts(raw string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			startP, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			endP, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil && startP >= 1 && endP <= 65535 && startP <= endP {
				for port := startP; port <= endP; port++ {
					ps := strconv.Itoa(port)
					if !seen[ps] {
						seen[ps] = true
						out = append(out, ps)
					}
				}
			}
			continue
		}
		if portNum, err := strconv.Atoi(p); err == nil && portNum >= 1 && portNum <= 65535 {
			ps := strconv.Itoa(portNum)
			if !seen[ps] {
				seen[ps] = true
				out = append(out, ps)
			}
		}
	}
	if len(out) == 0 {
		return []string{"80"}
	}
	return out
}

// PromptTargetSpec asks the user for a file, CIDR range, or direct hosts/IPs, validating that at least 1 target exists.
func PromptTargetSpec() (*TargetSpec, error) {
	modes := []string{
		"File Input (TXT file with domains, IPs, or CIDRs)",
		"CIDR / IP Range / Host Input (e.g., 104.16.0.0/24, 1.1.1.1-1.1.1.50, or example.com)",
	}
	mode := banner.PromptChoice("Select Target Input Source", modes, 0)

	if strings.HasPrefix(mode, "File Input") {
		for {
			fp := banner.PromptText("Enter file path", "", true)
			fp = strings.Trim(fp, "\"'")
			info, err := os.Stat(fp)
			if err != nil || info.IsDir() {
				fmt.Printf("   %s[!] File not found: %s%s\n", banner.Red, fp, banner.Reset)
				continue
			}
			spec := &TargetSpec{
				FilePath:    fp,
				Description: fmt.Sprintf("File: %s", fp),
			}
			if spec.CountTargets() == 0 {
				fmt.Printf("   %s[!] File contains 0 valid hosts/IPs/CIDRs.%s\n", banner.Red, banner.Reset)
				continue
			}
			return spec, nil
		}
	}

	for {
		raw := banner.PromptText("Enter Host(s), IP(s), CIDR(s), or Range(s) (comma-separated)", "", true)
		var entries []string
		for _, part := range strings.Split(raw, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				entries = append(entries, p)
			}
		}
		spec := &TargetSpec{
			Entries:     entries,
			Description: fmt.Sprintf("Targets: %s", raw),
		}
		if spec.CountTargets() == 0 {
			fmt.Printf("   %s[!] No valid targets found in input.%s\n", banner.Red, banner.Reset)
			continue
		}
		return spec, nil
	}
}
