package scanner

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type ProxyRouteScanner struct {
	TargetSpec *input.TargetSpec
	Methods    []string
	Ports      []string
	ProxyURL   *url.URL
	ProxyAuth  string
	No302      bool
	Timeout    time.Duration
	Retries    int
}

func NewProxyRouteScanner(spec *input.TargetSpec, methods, ports []string, proxyRaw, username, password string, no302 bool, timeoutSec, retries int) (*ProxyRouteScanner, error) {
	p := strings.TrimSpace(proxyRaw)
	if !strings.Contains(p, "://") {
		p = "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return nil, err
	}
	authHdr := ""
	if username != "" || password != "" {
		u.User = url.UserPassword(username, password)
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		authHdr = "Basic " + token
	}
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	if retries < 0 {
		retries = 2
	}
	return &ProxyRouteScanner{
		TargetSpec: spec,
		Methods:    methods,
		Ports:      ports,
		ProxyURL:   u,
		ProxyAuth:  authHdr,
		No302:      no302,
		Timeout:    time.Duration(timeoutSec) * time.Second,
		Retries:    retries,
	}, nil
}

func (prs *ProxyRouteScanner) TotalJobs() int64 {
	return prs.TargetSpec.CountTargets() * int64(len(prs.Ports)) * int64(len(prs.Methods))
}

func (prs *ProxyRouteScanner) MetadataDescription() string {
	return fmt.Sprintf("Mode: ProxyRoute (via %s) | %s | Ports: %s | Methods: %s",
		prs.ProxyURL.Host, prs.TargetSpec.Description, strings.Join(prs.Ports, ","), strings.Join(prs.Methods, ","))
}

func (prs *ProxyRouteScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-10s%s  %s%-5s%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "Method", banner.Reset,
		banner.Green, "Code", banner.Reset,
		banner.Yellow, "Proto", banner.Reset,
		banner.Magenta, "Server", banner.Reset,
		banner.Orange, "Port", banner.Reset,
		banner.Blue, "IP", banner.Reset,
		banner.White, "Host (via Proxy)", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-10s%s  %s%-5s%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "----------", banner.Reset,
		banner.Green, "-----", banner.Reset,
		banner.Yellow, "------", banner.Reset,
		banner.Magenta, "----------------", banner.Reset,
		banner.Orange, "------", banner.Reset,
		banner.Blue, "----------------", banner.Reset,
		banner.White, "--------------------", banner.Reset,
	)
	return []string{h1, h2}
}

func (prs *ProxyRouteScanner) ProduceJobs(emit func(job any) bool) {
	prs.TargetSpec.StreamTargets(func(host string) bool {
		for _, port := range prs.Ports {
			for _, method := range prs.Methods {
				if !emit(DirectJob{
					Method: strings.ToUpper(strings.TrimSpace(method)),
					Host:   host,
					Port:   port,
				}) {
					return false
				}
			}
		}
		return true
	})
}

func (prs *ProxyRouteScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(DirectJob)
	engine.SetCurrentStatus(fmt.Sprintf("%s (proxy) %s:%s", job.Method, job.Host, job.Port))

	ip := "-"
	if resolved, _, err := resolver.Default.ResolvePrimary(job.Host); err == nil {
		ip = resolved
	}

	useTLS := config.StandardTLSPorts[job.Port]
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	urlStr := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(job.Host, job.Port))

	hdrs := make(http.Header)
	if prs.ProxyAuth != "" {
		hdrs.Set("Proxy-Authorization", prs.ProxyAuth)
	}

	transport := &http.Transport{
		Proxy:              http.ProxyURL(prs.ProxyURL),
		ProxyConnectHeader: hdrs,
		TLSClientConfig:    buildPermissiveTLSConfig(job.Host, ""),
		DisableKeepAlives:  true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   prs.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	maxAttempts := 1 + prs.Retries
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequest(job.Method, urlStr, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", config.RandomUserAgent())
		for k, v := range config.DefaultBrowserHeaders {
			req.Header.Set(k, v)
		}
		if prs.ProxyAuth != "" {
			req.Header.Set("Proxy-Authorization", prs.ProxyAuth)
		}
		if config.MethodNeedsContentLengthZero(job.Method) {
			req.Header.Set("Content-Length", "0")
			req.ContentLength = 0
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				time.Sleep(time.Duration(attempt+1) * 150 * time.Millisecond)
			}
			continue
		}
		_ = resp.Body.Close()

		if prs.No302 && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308) {
			return
		}
		loc := resp.Header.Get("Location")
		if config.IsExcludedLocation(loc) {
			return
		}

		srv := resp.Header.Get("Server")
		if srv == "" {
			srv = "-"
		} else if len(srv) > 14 {
			srv = srv[:11] + "..."
		}

		colored := fmt.Sprintf(
			"%s%-10s%s  %s%-5d%s  %s%-6s%s  %s%-16s%s  %s%-6s%s  %s%-16s%s  %s%s%s",
			banner.Cyan, job.Method, banner.Reset,
			banner.Green, resp.StatusCode, banner.Reset,
			banner.Yellow, strings.ToUpper(scheme), banner.Reset,
			banner.Magenta, srv, banner.Reset,
			banner.Orange, job.Port, banner.Reset,
			banner.Blue, ip, banner.Reset,
			banner.White, job.Host, banner.Reset,
		)
		plain := fmt.Sprintf(
			"%-10s  %-5d  %-6s  %-16s  %-6s  %-16s  %s",
			job.Method, resp.StatusCode, strings.ToUpper(scheme), srv, job.Port, ip, job.Host,
		)
		engine.RecordSuccess(colored, plain)
		return
	}
}
