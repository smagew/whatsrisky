package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/perimeter"
	"github.com/smagew/whatsrisky/internal/report"
	"github.com/smagew/whatsrisky/internal/scan"
)

// cmdPerimeter maps a domain to its live assets and scans each of them, writing one
// report for the whole estate. It is the network scan's fan-out: discovery, then
// the same per-target passes across everything found.
func cmdPerimeter(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("perimeter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		authorized = flags.Bool("i-am-authorized", false, "confirm you may scan this domain and everything under it")
		netActive  = flags.Bool("net-active", false, "allow passes that send attack-shaped traffic (off by default)")
		passes     = flags.String("passes", "", "network passes per asset (default surface,testssl,nuclei)")
		outDir     = flags.String("out-dir", "", "directory for the report (default ./whatsrisky-reports)")
		format     = flags.String("format", "", "comma list: html,md,json (default all)")
		timeout    = flags.Int("timeout", 300, "per-tool timeout in seconds")
		aiProvider = flags.String("ai-provider", "", "backend for llm-recon if that pass is added")
		modelName  = flags.String("model", "", "model for llm-recon if that pass is added")
	)
	positional, err := parseInterleaved(flags, args)
	if err != nil {
		return 1
	}
	if len(positional) == 0 {
		fmt.Fprintln(stderr, "which domain? e.g. whatsrisky perimeter example.com --i-am-authorized")
		return 1
	}
	domain := positional[0]

	// The same authorization gate as the single-target scan, and sharper: this
	// enumerates and probes everything under the domain.
	if !*authorized {
		fmt.Fprintf(stderr, "Scanning a whole domain needs authorization: pass --i-am-authorized. "+
			"You are stating you may scan %s and every host under it.\n", domain)
		return 1
	}

	formats := scan.FormatChoices
	if *format != "" {
		formats = splitList(*format)
	}
	dir := *outDir
	if dir == "" {
		cwd, _ := os.Getwd()
		dir = filepath.Join(cwd, "whatsrisky-reports")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	workDir, err := os.MkdirTemp(dir, ".work-perimeter-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer os.RemoveAll(workDir)

	say := func(message string) { fmt.Fprintln(stderr, "  "+message) }
	fmt.Fprintf(stderr, "discovering the estate under %s\n", domain)
	assets, notes, err := perimeter.Discover(domain, time.Duration(*timeout)*time.Second, say)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printInventory(stdout, assets, notes)

	cfg := perimeter.Config{
		Domain: domain, NetActive: *netActive, AIProvider: *aiProvider, AIModel: *modelName,
		Timeout: time.Duration(*timeout) * time.Second, WorkDir: workDir, Progress: say,
	}
	if *passes != "" {
		cfg.Passes = splitList(*passes)
	}
	result := perimeter.Scan(cfg, assets, notes)
	result.Excludes = nil

	base := result.ScanID
	var written []string
	for _, f := range formats {
		path := filepath.Join(dir, base+"."+f)
		var writeErr error
		switch f {
		case "json":
			writeErr = report.WriteJSON(result, path)
		case "html":
			writeErr = report.WriteHTML(result, path)
		case "md":
			writeErr = report.WriteMarkdown(result, path)
		default:
			continue
		}
		if writeErr != nil {
			fmt.Fprintf(stderr, "writing %s: %v\n", path, writeErr)
			continue
		}
		written = append(written, path)
	}
	for _, path := range written {
		fmt.Fprintln(stdout, "report "+path)
	}
	return scan.ExitCode(result, "none")
}

// printInventory shows what was found before the scan detail: the estate at a
// glance, live things first, forgotten-looking ones easy to spot.
func printInventory(out *os.File, assets []perimeter.Asset, notes []string) {
	fmt.Fprintf(out, "\n%d asset(s) discovered:\n", len(assets))
	for _, a := range assets {
		mark := "·"
		if a.Alive {
			mark = "▪"
		}
		line := fmt.Sprintf("  %s %s", mark, a.Host)
		if a.Alive {
			line += fmt.Sprintf("  %d  %s", a.Status, a.URL)
			if len(a.Tech) > 0 {
				line += "  [" + strings.Join(a.Tech, ", ") + "]"
			}
		}
		fmt.Fprintln(out, line)
	}
	for _, note := range notes {
		fmt.Fprintln(out, "  ! "+note)
	}
	fmt.Fprintln(out)
}
