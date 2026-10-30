package resolver

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	FallbackDNSServers = []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"8.8.4.4:53",
	}
	Default = NewResolver(3 * time.Second)
)

type cacheEntry struct {
	ips []string
}

type ResilientResolver struct {
	timeout time.Duration
	cache   sync.Map
}

func NewResolver(timeout time.Duration) *ResilientResolver {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &ResilientResolver{
		timeout: timeout,
	}
}

// ResolveAll returns all IPv4/IPv6 addresses for a host, using cache -> OS DNS -> UDP Fallback -> TCP Fallback.
// Never drops a host due to transient UDP DNS packet loss.
func (r *ResilientResolver) ResolveAll(host string) ([]string, error) {
	// Fast path: if already an IP address literal, return immediately
	if addr, err := netip.ParseAddr(host); err == nil {
		ipStr := addr.String()
		return []string{ipStr}, nil
	}

	if cached, ok := r.cache.Load(host); ok {
		entry := cached.(cacheEntry)
		if len(entry.ips) > 0 {
			return entry.ips, nil
		}
	}

	// Stage 1: System Default Resolver (2 attempts)
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			ordered := prioritizeIPv4(addrs)
			r.cache.Store(host, cacheEntry{ips: ordered})
			return ordered, nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Stage 2: Public Fallback DNS Servers over UDP, then TCP (if ISP drops UDP bursts)
	for _, networkProto := range []string{"udp", "tcp"} {
		for _, dnsServer := range FallbackDNSServers {
			customRes := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: r.timeout}
					return d.DialContext(ctx, networkProto, dnsServer)
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
			addrs, err := customRes.LookupHost(ctx, host)
			cancel()
			if err == nil && len(addrs) > 0 {
				ordered := prioritizeIPv4(addrs)
				r.cache.Store(host, cacheEntry{ips: ordered})
				return ordered, nil
			}
		}
	}

	return nil, &net.DNSError{Err: "no such host after multi-DNS retries", Name: host, IsNotFound: true}
}

// ResolvePrimary returns the best primary IP and the full candidate list.
func (r *ResilientResolver) ResolvePrimary(host string) (string, []string, error) {
	ips, err := r.ResolveAll(host)
	if err != nil || len(ips) == 0 {
		return "", nil, err
	}
	return ips[0], ips, nil
}

func prioritizeIPv4(addrs []string) []string {
	var v4, v6 []string
	seen := make(map[string]bool)
	for _, a := range addrs {
		if seen[a] {
			continue
		}
		seen[a] = true
		if parsed, err := netip.ParseAddr(a); err == nil && parsed.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...)
}
