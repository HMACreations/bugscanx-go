package toolkit

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

func RunInteractiveDNSRecords() {
	rawTarget := banner.PromptText("Enter target domain", "", true)
	domain := input.NormalizeHost(rawTarget)
	if domain == "" {
		domain = rawTarget
	}

	fmt.Printf("\n %s[*] Performing Complete DNS Lookup for: %s%s\n", banner.Bold+banner.Cyan, domain, banner.Reset)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// A & AAAA Records via our resilient multi-DNS resolver
	fmt.Printf("\n %sA / AAAA Records (IPv4 & IPv6):%s\n", banner.Bold+banner.Green, banner.Reset)
	if ips, err := resolver.Default.ResolveAll(domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			fmt.Printf("  %s• %s%s\n", banner.Cyan, ip, banner.Reset)
		}
	} else {
		fmt.Printf("  %sNo A/AAAA records found%s\n", banner.Yellow, banner.Reset)
	}

	// CNAME Record
	fmt.Printf("\n %sCNAME Record:%s\n", banner.Bold+banner.Green, banner.Reset)
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil && cname != "" && cname != domain+"." {
		fmt.Printf("  %s• %s%s\n", banner.Cyan, cname, banner.Reset)
	} else {
		fmt.Printf("  %sNo CNAME alias found%s\n", banner.Yellow, banner.Reset)
	}

	// MX Records
	fmt.Printf("\n %sMX Records (Mail Servers):%s\n", banner.Bold+banner.Green, banner.Reset)
	if mxs, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil && len(mxs) > 0 {
		for _, mx := range mxs {
			fmt.Printf("  %s• %s (priority: %d)%s\n", banner.Cyan, mx.Host, mx.Pref, banner.Reset)
		}
	} else {
		fmt.Printf("  %sNo MX records found%s\n", banner.Yellow, banner.Reset)
	}

	// NS Records
	fmt.Printf("\n %sNS Records (Name Servers):%s\n", banner.Bold+banner.Green, banner.Reset)
	if nss, err := net.DefaultResolver.LookupNS(ctx, domain); err == nil && len(nss) > 0 {
		for _, ns := range nss {
			fmt.Printf("  %s• %s%s\n", banner.Cyan, ns.Host, banner.Reset)
		}
	} else {
		fmt.Printf("  %sNo NS records found%s\n", banner.Yellow, banner.Reset)
	}

	// TXT Records
	fmt.Printf("\n %sTXT Records:%s\n", banner.Bold+banner.Green, banner.Reset)
	if txts, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil && len(txts) > 0 {
		for _, txt := range txts {
			fmt.Printf("  %s• %s%s\n", banner.Cyan, txt, banner.Reset)
		}
	} else {
		fmt.Printf("  %sNo TXT records found%s\n", banner.Yellow, banner.Reset)
	}
}
