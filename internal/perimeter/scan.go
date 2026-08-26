package perimeter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/runner"
)

// Config is a perimeter scan's settings. It is deliberately small: perimeter is
// the observational passes across many assets, and the heavier per-target knobs
// stay on the single-target scan.
type Config struct {
	Domain     string
	Passes     []string // network passes to run per alive asset
	NetActive  bool
	AIProvider string
	AIModel    string
	Timeout    time.Duration
	WorkDir    string
	Progress   Progress
}

// DefaultPasses is what a perimeter scan runs on each asset unless told otherwise:
// the observational ones. llm-recon is left out by default — a paid model call per
// asset across a whole estate is a cost the caller should ask for.
var DefaultPasses = []string{"surface", "testssl", "nuclei"}

// Scan discovers the estate and runs the passes across every live asset, returning
// one report for the whole domain. Each finding already carries the asset it came
// from in its location, so the report reads per-asset without a new schema.
func Scan(cfg Config, assets []Asset, notes []string) model.Report {
	stamp := time.Now()
	report := model.Report{
		ProjectName: cfg.Domain,
		ProjectPath: cfg.Domain,
		ScanID:      slug(cfg.Domain) + "-" + stamp.Format("20060102-150405"),
		StartedAt:   stamp.Format("2006-01-02 15:04:05"),
		Status:      model.StatusRunning,
	}

	// The inventory is a first-class part of the result, so it is a tool of its own
	// whose message is the estate summary and whose note carries the gaps. Absence
	// of a discovery tool is thus visible, not silent.
	alive := AliveURLs(assets)
	discovery := model.ToolResult{
		Name:    "discovery",
		Status:  model.ToolOK,
		Message: fmt.Sprintf("%d asset(s) found, %d alive over HTTP", len(assets), len(alive)),
	}
	if len(notes) > 0 {
		discovery.Message += " — " + strings.Join(notes, "; ")
	}
	if len(assets) == 0 {
		discovery.Status = model.ToolError
	}
	report.Tools = append(report.Tools, discovery)

	passes := cfg.Passes
	if len(passes) == 0 {
		passes = DefaultPasses
	}

	// One ToolResult per pass, aggregated across assets: OK if it ran anywhere, the
	// reason kept when it never could (e.g. nuclei not installed).
	perPass := map[string]*model.ToolResult{}
	for _, name := range passes {
		perPass[name] = &model.ToolResult{Name: name, Status: model.ToolPending}
	}

	started := time.Now()
	for index, url := range alive {
		cfg.Progress.say(fmt.Sprintf("scanning %s (%d/%d)", url, index+1, len(alive)))
		config := runner.Config{
			Target: url, WorkDir: cfg.WorkDir, NetActive: cfg.NetActive,
			AIProvider: cfg.AIProvider, AIModel: cfg.AIModel,
			NucleiTimeout:  cfg.Timeout,
			SurfaceTimeout: 60 * time.Second,
		}
		for _, name := range passes {
			built, err := runner.New(name, config)
			aggregate := perPass[name]
			if err != nil {
				aggregate.Status = model.ToolError
				aggregate.Message = err.Error()
				continue
			}
			result := runner.Run(built, func(string) {})
			report.Findings = append(report.Findings, result.Findings...)
			// The aggregate status is the best any asset achieved: one asset where
			// nuclei ran means the pass ran, even if another was unreachable.
			if statusRank(result.Status) < statusRank(aggregate.Status) || aggregate.Status == model.ToolPending {
				aggregate.Status = result.Status
				if result.Status != model.ToolOK {
					aggregate.Message = result.Message
				}
			}
		}
	}

	for _, name := range passes {
		report.Tools = append(report.Tools, *perPass[name])
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		return report.Findings[i].Severity.Rank() < report.Findings[j].Severity.Rank()
	})

	report.DurationS = time.Since(started).Seconds()
	report.FinishedAt = time.Now().Format("2006-01-02 15:04:05")
	report.Status = model.StatusComplete
	for _, tool := range report.Tools {
		if !tool.OK() {
			report.Status = model.StatusPartial
		}
	}
	return report
}

// statusRank orders tool statuses so "ran and found" beats "missing" when a pass
// is aggregated over many assets. Lower is better.
func statusRank(status string) int {
	switch status {
	case model.ToolOK:
		return 0
	case model.ToolError:
		return 1
	case model.ToolMissing:
		return 2
	default:
		return 3
	}
}

func slug(domain string) string {
	var b strings.Builder
	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
