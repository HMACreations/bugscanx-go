package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
	"github.com/FreeNetLabs/bugscanx-go/internal/input"
	"github.com/FreeNetLabs/bugscanx-go/internal/resolver"
)

type PingJob struct {
	Host string
	Port string
}

type PingScanner struct {
	TargetSpec *input.TargetSpec
	Ports      []string
	Timeout    time.Duration
	Retries    int
}

func NewPingScanner(spec *input.TargetSpec, ports []string, timeoutSec, retries int) *PingScanner {
	if len(ports) == 0 {
		ports = []string{"443"}
	}
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	if retries < 0 {
		retries = 2
	}
	return &PingScanner{
		TargetSpec: spec,
		Ports:      ports,
		Timeout:    time.Duration(timeoutSec) * time.Second,
		Retries:    retries,
	}
}

func (ps *PingScanner) TotalJobs() int64 {
	return ps.TargetSpec.CountTargets() * int64(len(ps.Ports))
}

func (ps *PingScanner) MetadataDescription() string {
	return fmt.Sprintf("Mode: TCP Ping | %s | Ports: %s", ps.TargetSpec.Description, strings.Join(ps.Ports, ","))
}

func (ps *PingScanner) TableHeaders() []string {
	h1 := fmt.Sprintf("%s%-6s%s  %s%-10s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "Port", banner.Reset,
		banner.Green, "Latency", banner.Reset,
		banner.Yellow, "IP", banner.Reset,
		banner.White, "Host", banner.Reset,
	)
	h2 := fmt.Sprintf("%s%-6s%s  %s%-10s%s  %s%-16s%s  %s%s%s",
		banner.Cyan, "------", banner.Reset,
		banner.Green, "----------", banner.Reset,
		banner.Yellow, "----------------", banner.Reset,
		banner.White, "--------------------", banner.Reset,
	)
	return []string{h1, h2}
}

func (ps *PingScanner) ProduceJobs(emit func(job any) bool) {
	ps.TargetSpec.StreamTargets(func(host string) bool {
		for _, port := range ps.Ports {
			if !emit(PingJob{Host: host, Port: port}) {
				return false
			}
		}
		return true
	})
}

func (ps *PingScanner) ExecuteJob(rawJob any, engine *Engine) {
	job := rawJob.(PingJob)
	engine.SetCurrentStatus(fmt.Sprintf("Ping %s:%s", job.Host, job.Port))

	ips, err := resolver.Default.ResolveAll(job.Host)
	if err != nil || len(ips) == 0 {
		return
	}

	maxIPs := len(ips)
	if maxIPs > 2 {
		maxIPs = 2
	}

	for i := 0; i < maxIPs; i++ {
		ip := ips[i]
		for attempt := 0; attempt <= ps.Retries; attempt++ {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, job.Port), ps.Timeout)
			if err == nil {
				rtt := time.Since(start).Milliseconds()
				_ = conn.Close()
				rttStr := fmt.Sprintf("%dms", rtt)
				colored := fmt.Sprintf(
					"%s%-6s%s  %s%-10s%s  %s%-16s%s  %s%s%s",
					banner.Cyan, job.Port, banner.Reset,
					banner.Green, rttStr, banner.Reset,
					banner.Yellow, ip, banner.Reset,
					banner.White, job.Host, banner.Reset,
				)
				plain := fmt.Sprintf("%-6s  %-10s  %-16s  %s", job.Port, rttStr, ip, job.Host)
				engine.RecordSuccess(colored, plain)
				return
			}
		}
	}
}
