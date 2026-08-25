// Package model holds the vocabulary every scanner and every report writer shares:
// one severity scale, one finding shape, one category vocabulary.
package model

import (
	"math"
	"strings"
)

// Severity is the single scale every scanner's native levels are mapped onto.
// The mapping rationale for each scanner lives with its runner.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Order is priority order: what to fix first comes first.
var Order = []Severity{Critical, High, Medium, Low, Info}

// weights feed the risk score. A critical is not "four times" a medium; the scale
// is deliberately steep because the score saturates.
var weights = map[Severity]float64{
	Critical: 40,
	High:     10,
	Medium:   3,
	Low:      1,
	Info:     0.1,
}

// aliases covers what the scanners actually write.
var aliases = map[string]Severity{
	"CRITICAL": Critical, "BLOCKER": Critical,
	"HIGH": High, "ERROR": High, "MAJOR": High,
	"MEDIUM": Medium, "MODERATE": Medium, "WARNING": Medium, "WARN": Medium,
	"LOW": Low, "MINOR": Low, "NOTE": Low,
	"INFO": Info, "INFORMATIONAL": Info, "UNKNOWN": Info, "NONE": Info,
}

// Rank is the index in Order; lower is worse.
func (s Severity) Rank() int {
	for i, candidate := range Order {
		if candidate == s {
			return i
		}
	}
	return len(Order) - 1
}

// Weight is this severity's contribution to the risk score.
func (s Severity) Weight() float64 { return weights[s] }

// ParseSeverity maps a scanner's word onto the shared scale, falling back to
// def when it means nothing to us.
func ParseSeverity(raw string, def Severity) Severity {
	if mapped, ok := aliases[strings.ToUpper(strings.TrimSpace(raw))]; ok {
		return mapped
	}
	return def
}

// RiskScore is a saturating weighted aggregate: it ranks projects, it does not
// measure them. 100·(1−e^(−Σw/120)) keeps a single critical meaningful (~28)
// without letting a hundred lows outweigh it.
func RiskScore(findings []Finding) int {
	total := 0.0
	for _, finding := range findings {
		if finding.IsActive() {
			total += finding.Severity.Weight()
		}
	}
	if total <= 0 {
		return 0
	}
	score := roundHalfEven(100 * (1 - math.Exp(-total/120)))
	if score > 100 {
		return 100
	}
	return score
}

// roundHalfEven matches Python's round(), which the reference implementation used;
// the parity tests compare scores, so the tie-breaking rule has to agree.
func roundHalfEven(value float64) int {
	floor := math.Floor(value)
	diff := value - floor
	switch {
	case diff > 0.5:
		return int(floor) + 1
	case diff < 0.5:
		return int(floor)
	case math.Mod(floor, 2) == 0:
		return int(floor)
	default:
		return int(floor) + 1
	}
}
