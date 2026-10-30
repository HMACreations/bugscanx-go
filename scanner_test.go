package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/scanner"
)

func TestInputNormalizationAndCIDR(t *testing.T) {
	spec := &input.TargetSpec{
		Entries: []string{
			"192.0.2.1/32",          // Single IP CIDR (Python returned 0 hosts!)
			"192.0.2.10/31",         // RFC 3021 /31 (Python returned 0 hosts!)
			"192.0.2.20-192.0.2.22", // IP Range (3 IPs)
			"https://sub.example.com:8443/login?x=1",
			"*.wildcard.example.org",
		},
	}

	var got []string
	spec.StreamTargets(func(target string) bool {
		got = append(got, target)
		return true
	})

	if int64(len(got)) != spec.CountTargets() {
		t.Fatalf("expected CountTargets (%d) == streamed count (%d)", spec.CountTargets(), len(got))
	}
	if len(got) != 8 {
		t.Fatalf("expected 8 targets, got %d: %v", len(got), got)
	}
}

func TestAllMethodsIncludingQueryAndWebDAV(t *testing.T) {
	// Start local HTTP server that accepts GET, HEAD, POST, QUERY, PROPFIND, OPTIONS, PATCH, etc.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "ZeroRated-Edge/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK " + r.Method))
	}))
	defer srv.Close()

	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	methodsToTest := []string{"GET", "HEAD", "POST", "OPTIONS", "QUERY", "PROPFIND", "REPORT", "SEARCH", "PATCH", "PURGE", "CONNECT"}

	outFile := filepath.Join(t.TempDir(), "hits.txt")
	spec := &input.TargetSpec{Entries: []string{"127.0.0.1"}}

	ds := scanner.NewDirectScanner(spec, methodsToTest, []string{port}, true, 2, 1, "zero.example.com", "")
	eng := scanner.NewEngine(10, outFile)
	eng.Run(ds)

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed reading output file: %v", err)
	}
	outText := string(data)
	for _, m := range methodsToTest {
		if !strings.Contains(outText, m) {
			t.Errorf("expected method %s to be recorded as working hit, but was missing from output:\n%s", m, outText)
		}
	}
	if len(config.AllExtendedMethods) < 30 {
		t.Errorf("expected at least 30 extended methods in config, got %d", len(config.AllExtendedMethods))
	}
}

func TestWebSocket101KeepAliveDoesNotHangOrSkip(t *testing.T) {
	// Simulate a real WebSocket tunnel server that sends 101 Switching Protocols and keeps the TCP socket open!
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nServer: Cloudflare\r\n\r\n"))
				// Keep socket open for 10 seconds (Python BugScanX hung here and dropped the 101 hit!)
				time.Sleep(10 * time.Second)
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	outFile := filepath.Join(t.TempDir(), "ws_hits.txt")
	spec := &input.TargetSpec{Entries: []string{"127.0.0.1"}}

	start := time.Now()
	ps := scanner.NewProxyCheckScanner(spec, []string{port}, "ws.example.com", "", 2, 0)
	eng := scanner.NewEngine(5, outFile)
	eng.Run(ps)
	elapsed := time.Since(start)

	if elapsed > 1500*time.Millisecond {
		t.Errorf("ProxyCheckScanner took too long (%s), should return immediately after \\r\\n\\r\\n", elapsed)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed reading ws output: %v", err)
	}
	if !strings.Contains(string(data), "101") {
		t.Fatalf("expected 101 Switching Protocols hit in output, got:\n%s", fmt.Sprintf("%s", string(data)))
	}
}
