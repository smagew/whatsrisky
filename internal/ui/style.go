// Package ui is the terminal interface: a settings form and a live progress
// screen, over the same scan.Options and scan.Run as the CLI.
package ui

import "github.com/charmbracelet/lipgloss"

// One place for colour, as in the HTML viewer and in whydiff: the two windows sit
// side by side, so they use the same palette. Everything else refers to these.
var (
	inkColor     = lipgloss.Color("252")
	ink2Color    = lipgloss.Color("249")
	ink3Color    = lipgloss.Color("245")
	lineColor    = lipgloss.Color("238")
	markColor    = lipgloss.Color("179")
	flagColor    = lipgloss.Color("174")
	passColor    = lipgloss.Color("108")
	cautionColor = lipgloss.Color("179")
	panelColor   = lipgloss.Color("236")
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(inkColor)
	sectionStyle  = lipgloss.NewStyle().Bold(true).Foreground(markColor)
	labelStyle    = lipgloss.NewStyle().Foreground(ink3Color)
	valueStyle    = lipgloss.NewStyle().Foreground(inkColor)
	dimStyle      = lipgloss.NewStyle().Foreground(ink3Color)
	mutedStyle    = lipgloss.NewStyle().Foreground(ink2Color)
	focusStyle    = lipgloss.NewStyle().Foreground(markColor).Bold(true)
	selectedStyle = lipgloss.NewStyle().Background(panelColor).Foreground(inkColor)
	okStyle       = lipgloss.NewStyle().Foreground(passColor)
	badStyle      = lipgloss.NewStyle().Foreground(flagColor)
	warnStyle     = lipgloss.NewStyle().Foreground(cautionColor)
	commandStyle  = lipgloss.NewStyle().Foreground(passColor)
	panelStyle    = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lineColor).PaddingLeft(2)
	helpStyle = lipgloss.NewStyle().Foreground(ink3Color)
	// The primary action needs to look like one: a help line is not a button.
	actionStyle = lipgloss.NewStyle().Background(passColor).Foreground(lipgloss.Color("235")).Bold(true)
)

// severityStyle expresses weight with tone, not five accents - the same restraint
// the HTML viewer keeps.
func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(flagColor).Bold(true)
	case "HIGH":
		return lipgloss.NewStyle().Foreground(flagColor)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(cautionColor)
	case "LOW":
		return mutedStyle
	default:
		return dimStyle
	}
}
