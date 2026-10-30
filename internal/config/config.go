package config

import (
	"math/rand"
	"strings"
)

const Version = "2.0.0-go"

// StandardMethods includes RFC 9110 core HTTP methods.
var StandardMethods = []string{
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"OPTIONS",
	"TRACE",
	"PATCH",
	"CONNECT",
}

// ModernAndBypassMethods includes standard methods + newer IETF methods (like QUERY, PRI)
// and high-success firewall/DPI bypass methods (WebDAV, CDN purge, etc.).
var ModernAndBypassMethods = []string{
	"GET",
	"HEAD",
	"POST",
	"OPTIONS",
	"QUERY",    // IETF HTTP QUERY Method (safe, idempotent request with body support)
	"PATCH",
	"PUT",
	"DELETE",
	"TRACE",
	"CONNECT",
	"PROPFIND", // WebDAV - frequently bypasses GET/POST DPI rules
	"REPORT",   // WebDAV versioning report
	"SEARCH",   // WebDAV/DASL search
	"PURGE",    // Squid/Varnish/Cloudflare/Fastly cache purge
	"MKCOL",    // WebDAV collection
	"ACL",      // WebDAV access control
	"PRI",      // HTTP/2 connection preface method
}

// AllExtendedMethods includes every standard, modern (QUERY/PRI), WebDAV, DeltaV, and proxy method.
var AllExtendedMethods = []string{
	// Core RFC 9110
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"OPTIONS",
	"TRACE",
	"PATCH",
	"CONNECT",
	// Newer IETF & HTTP/2
	"QUERY",
	"PRI",
	// WebDAV / DeltaV / CalDAV / CDN Extended
	"PROPFIND",
	"PROPPATCH",
	"MKCOL",
	"COPY",
	"MOVE",
	"LOCK",
	"UNLOCK",
	"SEARCH",
	"REPORT",
	"ACL",
	"PURGE",
	"LINK",
	"UNLINK",
	"MKCALENDAR",
	"ORDERPATCH",
	"VERSION-CONTROL",
	"CHECKIN",
	"CHECKOUT",
	"UNCHECKOUT",
	"MKWORKSPACE",
	"UPDATE",
	"LABEL",
	"MERGE",
	"BASELINE-CONTROL",
	"MKACTIVITY",
}

// MethodNeedsContentLengthZero returns true if middleboxes/servers commonly require
// Content-Length: 0 when no body is sent, preventing false 411 Length Required or timeouts.
func MethodNeedsContentLengthZero(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "QUERY", "PROPFIND", "PROPPATCH", "REPORT", "SEARCH", "LOCK", "MERGE", "UPDATE", "ORDERPATCH":
		return true
	default:
		return false
	}
}

//ExcludeLocations contains known ISP zero-balance / captive portal redirect URLs or substrings.
var ExcludeLocations = []string{
	"jio.com/BalanceExhaust",
	"balanceexhaust",
	"captive.apple.com",
	"connectivitycheck.gstatic.com",
	"recharge",
	"topup",
	"portal.isp",
	"outofdata",
}

// IsExcludedLocation checks if a Location redirect header matches a known ISP captive portal.
func IsExcludedLocation(location string) bool {
	if location == "" {
		return false
	}
	locLower := strings.ToLower(location)
	for _, excl := range ExcludeLocations {
		if strings.Contains(locLower, strings.ToLower(excl)) {
			return true
		}
	}
	return false
}

// StandardTLSPorts lists ports that natively expect TLS/HTTPS handshakes by default.
var StandardTLSPorts = map[string]bool{
	"443":  true,
	"8443": true,
	"2053": true, // Cloudflare HTTPS
	"2083": true, // Cloudflare HTTPS / cPanel SSL
	"2087": true, // Cloudflare HTTPS / WHM SSL
	"2096": true, // Cloudflare HTTPS / Webmail SSL
	"9443": true,
	"4443": true,
}

// CommonTunnelingPorts lists the primary ports used in bug host & tunneling discovery.
var CommonTunnelingPorts = []int{
	80, 443, 8080, 8443, 8888, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
	21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1080, 1723, 3128, 3306, 3389, 5900, 8000, 8008, 8880, 9000, 9443,
}

var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
}

func RandomUserAgent() string {
	return UserAgents[rand.Intn(len(UserAgents))]
}

var DefaultBrowserHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"Accept-Language":           "en-US,en;q=0.9",
	"Upgrade-Insecure-Requests": "1",
	"Cache-Control":             "no-cache",
}

var BypassIPHeaders = map[string]string{
	"X-Originating-IP": "127.0.0.1",
	"X-Forwarded-For":  "127.0.0.1",
	"X-Remote-IP":      "127.0.0.1",
	"X-Remote-Addr":    "127.0.0.1",
	"X-Client-IP":      "127.0.0.1",
	"X-Real-IP":        "127.0.0.1",
	"True-Client-IP":   "127.0.0.1",
}

type CDNIndicator struct {
	Headers       []string
	HeaderPrefix  []string
	ServerSubstrs []string
	CNAMEPatterns []string
}

var CDNProviders = map[string]CDNIndicator{
	"Cloudflare": {
		Headers:       []string{"cf-ray", "cf-cache-status", "cf-request-id", "cf-visitor", "cf-connecting-ip", "cf-ipcountry", "cf-railgun", "cf-polished", "cf-apo-via"},
		ServerSubstrs: []string{"cloudflare"},
		CNAMEPatterns: []string{"cloudflare.net", "cloudflare.com", "cloudflare-dns.com", "cdn.cloudflare.net"},
	},
	"Amazon CloudFront": {
		Headers:       []string{"x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id", "x-cache"},
		HeaderPrefix:  []string{"x-amz-cf-"},
		ServerSubstrs: []string{"cloudfront", "amazonS3"},
		CNAMEPatterns: []string{"cloudfront.net", "amazonaws.com"},
	},
	"Google Cloud CDN": {
		Headers:       []string{"x-goog-cache-status", "x-goog-generation", "x-goog-metageneration", "x-guploader-uploadid", "via"},
		HeaderPrefix:  []string{"x-goog-"},
		ServerSubstrs: []string{"gws", "gfe2", "esf", "sffe"},
		CNAMEPatterns: []string{"googleusercontent.com", "googlevideo.com", "google.com", "gstatic.com", "googleapis.com", "1e100.net"},
	},
	"Akamai": {
		Headers:       []string{"x-akamai-transformed", "akamai-cache-status", "akamai-origin-hop", "x-akamai-request-id", "x-akamai-ssl-client-sid", "akamai-grn", "x-akamai-config-log-detail"},
		HeaderPrefix:  []string{"x-akamai-", "akamai-"},
		ServerSubstrs: []string{"akamaighost", "akamai"},
		CNAMEPatterns: []string{"akamai.net", "edgekey.net", "edgesuite.net", "akamaized.net", "akamaiedge.net", "akamaitechnologies.com", "akamaihd.net"},
	},
	"Fastly": {
		Headers:       []string{"fastly-debug", "x-served-by", "x-cache-hits", "x-timer", "fastly-ff", "x-fastly-request-id"},
		HeaderPrefix:  []string{"fastly-", "x-fastly-"},
		ServerSubstrs: []string{"artisanal"},
		CNAMEPatterns: []string{"fastly.net", "fastlylb.net"},
	},
	"Microsoft Azure": {
		Headers:       []string{"x-azure-ref", "x-azure-requestid", "x-msedge-ref", "x-ec-custom-error", "x-azure-fdid"},
		HeaderPrefix:  []string{"x-azure-", "x-msedge-"},
		CNAMEPatterns: []string{"azureedge.net", "msedge.net", "azure-edge.net", "trafficmanager.net", "azurefd.net"},
	},
	"BunnyCDN": {
		Headers:       []string{"cdn-pullzone", "cdn-uid", "cdn-requestid", "cdn-cache", "cdn-zone", "bunnycdn-cache-tag"},
		ServerSubstrs: []string{"bunnycdn"},
		CNAMEPatterns: []string{"b-cdn.net"},
	},
	"Sucuri": {
		Headers:       []string{"x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"},
		HeaderPrefix:  []string{"x-sucuri-"},
		ServerSubstrs: []string{"sucuri"},
		CNAMEPatterns: []string{"sucuri.net"},
	},
	"Imperva / Incapsula": {
		Headers:       []string{"x-iinfo", "incap-ses", "visid-incap", "x-cdn"},
		CNAMEPatterns: []string{"incapdns.net", "imperva.com", "impervadns.net"},
	},
	"CacheFly": {
		HeaderPrefix:  []string{"x-cf-"},
		ServerSubstrs: []string{"cachefly"},
		CNAMEPatterns: []string{"cachefly.net"},
	},
	"Alibaba Cloud CDN": {
		HeaderPrefix:  []string{"ali-cdn-", "x-oss-", "eagleid"},
		ServerSubstrs: []string{"tengine"},
		CNAMEPatterns: []string{"alikunlun.com", "alicdn.com"},
	},
	"Tencent Cloud CDN": {
		HeaderPrefix:  []string{"x-nws-", "x-daa-tunnel"},
		CNAMEPatterns: []string{"qcloudcdn.com", "myqcloud.com", "dnsv1.com"},
	},
}
