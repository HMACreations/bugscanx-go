package scanner

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FreeNetLabs/bugscanx-go/internal/banner"
)

// Runner is implemented by each specific scan mode (Direct, ProxyTest, ProxyRoute, SSL, Ping).
type Runner interface {
	TotalJobs() int64
	MetadataDescription() string
	TableHeaders() []string
	ProduceJobs(emit func(job any) bool)
	ExecuteJob(job any, engine *Engine)
}

type Engine struct {
	Workers      int
	OutputFile   string
	total        int64
	scanned      atomic.Int64
	successCount atomic.Int64
	lastTarget   atomic.Value // string
	startTime    time.Time

	outMu     sync.Mutex
	file      *os.File
	fileBuf   *bufio.Writer
}

func NewEngine(workers int, outputFile string) *Engine {
	if workers <= 0 {
		workers = 100
	}
	e := &Engine{
		Workers:    workers,
		OutputFile: outputFile,
	}
	e.lastTarget.Store("Initializing...")
	return e
}

func (e *Engine) SetCurrentStatus(status string) {
	e.lastTarget.Store(status)
}

func (e *Engine) RecordSuccess(coloredLine, plainLine string) {
	e.successCount.Add(1)
	e.outMu.Lock()
	defer e.outMu.Unlock()

	// Clear current progress line, print the hit, and flush
	fmt.Fprintf(os.Stdout, "\r\033[2K%s\n", coloredLine)
	if e.fileBuf != nil && plainLine != "" {
		_, _ = e.fileBuf.WriteString(plainLine + "\n")
		_ = e.fileBuf.Flush()
	}
}

func (e *Engine) printLineBoth(coloredLine, plainLine string) {
	e.outMu.Lock()
	defer e.outMu.Unlock()
	fmt.Fprintf(os.Stdout, "\r\033[2K%s\n", coloredLine)
	if e.fileBuf != nil && plainLine != "" {
		_, _ = e.fileBuf.WriteString(plainLine + "\n")
		_ = e.fileBuf.Flush()
	}
}

func (e *Engine) renderProgress(done bool) {
	e.outMu.Lock()
	defer e.outMu.Unlock()

	scanned := e.scanned.Load()
	total := e.total
	if total <= 0 {
		total = 1
	}
	pct := float64(scanned) / float64(total) * 100.0
	if pct > 100.0 {
		pct = 100.0
	}
	hits := e.successCount.Load()
	elapsed := time.Since(e.startTime).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(scanned) / elapsed
	}

	status, _ := e.lastTarget.Load().(string)
	if done {
		status = banner.Colorize("Scan Completed", banner.Bold+banner.Green)
	} else if len(status) > 38 {
		status = status[:35] + "..."
	}

	line := fmt.Sprintf(
		"%s%.2f%%%s │ %s%d/%d%s │ Hits: %s%d%s │ %s%.0f/s%s │ %s",
		banner.Bold+banner.Cyan, pct, banner.Reset,
		banner.White, scanned, e.total, banner.Reset,
		banner.Bold+banner.Green, hits, banner.Reset,
		banner.Yellow, rate, banner.Reset,
		status,
	)
	fmt.Fprintf(os.Stdout, "\r\033[2K%s", line)
}

func (e *Engine) Run(runner Runner) {
	e.total = runner.TotalJobs()
	e.scanned.Store(0)
	e.successCount.Store(0)
	e.startTime = time.Now()

	if e.OutputFile != "" {
		f, err := os.OpenFile(e.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			e.file = f
			e.fileBuf = bufio.NewWriterSize(f, 32*1024)
			defer func() {
				_ = e.fileBuf.Flush()
				_ = e.file.Close()
			}()
			ts := time.Now().Format("2006-01-02 15:04:05")
			_, _ = fmt.Fprintf(e.fileBuf, "\n=== Scan Time: %s | %s ===\n", ts, runner.MetadataDescription())
		}
	}

	// Hide cursor during scan, restore on exit
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h\n")

	fmt.Println()
	headers := runner.TableHeaders()
	for _, h := range headers {
		e.printLineBoth(h, stripANSI(h))
	}

	jobsChan := make(chan any, e.Workers*4)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < e.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				runner.ExecuteJob(job, e)
				e.scanned.Add(1)
			}
		}()
	}

	// Start throttled UI progress ticker (10 updates/sec, zero lock contention for workers)
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.renderProgress(false)
			case <-stopProgress:
				e.renderProgress(true)
				return
			}
		}
	}()

	// Stream jobs into channel
	runner.ProduceJobs(func(job any) bool {
		jobsChan <- job
		return true
	})
	close(jobsChan)

	wg.Wait()
	close(stopProgress)
	<-progressDone

	elapsed := time.Since(e.startTime).Round(time.Millisecond)
	fmt.Printf("\n\n %s[✓] Finished in %s | Scanned: %d | Working Hits: %d%s\n",
		banner.Bold+banner.Green, elapsed, e.scanned.Load(), e.successCount.Load(), banner.Reset)
	if e.OutputFile != "" {
		fmt.Printf(" %s[✓] Saved results to: %s%s\n", banner.Cyan, e.OutputFile, banner.Reset)
	}
}

func stripANSI(s string) string {
	out := make([]byte, 0, len(s))
	inEsc := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
				inEsc = false
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
