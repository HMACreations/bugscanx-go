package scanner

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/config"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type PortScanJob struct {
	Host string
	IP   string
	Port int
}

type PortScanner struct {
	Host    string
	IP      string
	Ports   []int
	Timeout time.Duration
	Retries int

	mu        sync.Mutex
	OpenPorts []int
}

func RunInteractivePortScanner() {
	targetRaw := banner.PromptText("Enter target hostname or IP", "", true)
	target := input.NormalizeHost(targetRaw)
	if target == "" {
		target = targetRaw
	}

	ip, allIPs, err := resolver.Default.ResolvePrimary(target)
	if err != nil {
		fmt.Printf("\n %s[!] Failed to resolve hostname: %s%s\n", banner.Bold+banner.Red, target, banner.Reset)
		return
	}

	scanChoices := []string{
		"Common Tunneling & Service Ports (38 ports: 80, 443, 8080, 8443, Cloudflare ports, SSH, etc.)",
		"All Ports (1 - 65535 inclusive)",
		"Custom Port Range (e.g., 1-10000 or 80,443,8000-9000)",
	}
	scanType := banner.PromptChoice("Select Port Scan Scope", scanChoices, 0)

	var ports []int
	switch {
	case scanType == scanChoices[0]:
		ports = append([]int{}, config.CommonTunnelingPorts...)
	case scanType == scanChoices[1]:
		// Fixes Python's range(1, 65535) off-by-one bug! Includes port 65535.
		ports = make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			ports[i-1] = i
		}
	default:
		customRaw := banner.PromptText("Enter ports or ranges", "80,443,8080,8443", true)
		for _, ps := range input.ParsePorts(customRaw) {
			if p, err := strconv.Atoi(ps); err == nil {
				ports = append(ports, p)
			}
		}
	}

	defaultWorkers := 300
	if len(ports) > 5000 {
		defaultWorkers = 800
	}
	workers := banner.PromptInt("Enter concurrency (goroutines)", defaultWorkers, 1)
	timeoutSec := banner.PromptInt("Enter timeout per port (seconds)", 2, 1)
	outFile := banner.PromptText("Enter output file (optional, press Enter to skip)", "open_ports.txt", false)

	fmt.Printf("\n %sTarget Info:%s\n", banner.Bold+banner.Green, banner.Reset)
	fmt.Printf("  • Host: %s\n", target)
	fmt.Printf("  • Primary IP: %s (All IPs: %v)\n", ip, allIPs)
	fmt.Printf("  • Total Ports: %d\n", len(ports))

	ps := &PortScanner{
		Host:    target,
		IP:      ip,
		Ports:   ports,
		Timeout: time.Duration(timeoutSec) * time.Second,
		Retries: 1,
	}

	engine := NewEngine(workers, outFile)
	engine.Run(ps)

	ps.mu.Lock()
	sort.Ints(ps.OpenPorts)
	openList := append([]int{}, ps.OpenPorts...)
	ps.mu.Unlock()

	if len(openList) == 0 {
		fmt.Printf("\n %s[!] No open ports found on %s (%s).%s\n", banner.Yellow, target, ip, banner.Reset)
	} else {
		var portStrs []string
		for _, p := range openList {
			portStrs = append(portStrs, strconv.Itoa(p))
		}
		fmt.Printf("\n %s[✓] Open Ports Summary (%d): %s%s\n",
			banner.Bold+banner.Green, len(openList), fmt.Sprintf("%v", portStrs), banner.Reset)
	}
}

func (ps *PortScanner) TotalJobs() int64 {
	return int64(len(ps.Ports))
}

func (ps *PortScanner) MetadataDescription() string {
	return fmt.Sprintf("Mode: PortScanner | Host: %s (%s) | Total Ports: %d", ps.Host, ps.IP, len(ps.Ports))
}

func (ps *PortScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-8s%s  %s%-10s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "Port", banner.Reset,
		banner.Green, "Latency", banner.Reset,
		banner.Yellow, "Service Hint", banner.Reset,
		banner.White, "Target", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-8s%s  %s%-10s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "--------", banner.Reset,
		banner.Green, "----------", banner.Reset,
		banner.Yellow, "----------------", banner.Reset,
		banner.White, "--------------------", banner.Reset,
	)
	return []string{h1, h2}
}

func (ps *PortScanner) ProduceJobs(emit func(job any) bool) {
	for _, port := range ps.Ports {
		if !emit(PortScanJob{Host: ps.Host, IP: ps.IP, Port: port}) {
			return
		}
	}
}

func (ps *PortScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(PortScanJob)
	portStr := strconv.Itoa(job.Port)
	engine.SetCurrentStatus(fmt.Sprintf("%s:%s", job.IP, portStr))

	for attempt := 0; attempt <= ps.Retries; attempt++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(job.IP, portStr), ps.Timeout)
		if err == nil {
			rtt := time.Since(start).Milliseconds()
			_ = conn.Close()

			ps.mu.Lock()
			ps.OpenPorts = append(ps.OpenPorts, job.Port)
			ps.mu.Unlock()

			svc := guessServiceName(job.Port)
			rttStr := fmt.Sprintf("%dms", rtt)
			colored := fmt.Sprintf(
				"%s%-8d%s  %s%-10s%s  %s%-16s%s  %s%s (%s)%s",
				banner.Bold+banner.Green, job.Port, banner.Reset,
				banner.Cyan, rttStr, banner.Reset,
				banner.Yellow, svc, banner.Reset,
				banner.White, job.Host, job.IP, banner.Reset,
			)
			plain := fmt.Sprintf("%-8d  %-10s  %-16s  %s (%s)", job.Port, rttStr, svc, job.Host, job.IP)
			engine.RecordSuccess(colored, plain)
			return
		}
	}
}

func guessServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8080, 8000, 8008, 8880, 2052, 2082, 2086, 2095:
		return "HTTP"
	case 443, 8443, 2053, 2083, 2087, 2096, 9443:
		return "HTTPS/TLS"
	case 1080:
		return "SOCKS"
	case 3128, 8888:
		return "HTTP-Proxy"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	default:
		return "TCP-Open"
	}
}
