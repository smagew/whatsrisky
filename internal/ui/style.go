// Package ui is the terminal interface: a settings screen and a live progress
// screen, over the same scan.Options and scan.Run as the CLI.
//
// It is built on tview, which is a widget toolkit: the checkboxes, lists and
// fields here are the library's, and so is the focus handling and the mouse. The
// previous interface used Bubble Tea, which is an event loop rather than a
// widget set, and the form had to be written by hand.
package ui

import "github.com/gdamore/tcell/v2"

// One place for colour, as in the HTML viewer and in whydiff: the two windows sit
// side by side, so they use the same palette. Everything else refers to these.
const (
	inkColor     = tcell.Color252
	ink2Color    = tcell.Color249
	ink3Color    = tcell.Color245
	lineColor    = tcell.Color238
	fieldColor   = tcell.Color236
	markColor    = tcell.Color179
	flagColor    = tcell.Color174
	passColor    = tcell.Color108
	cautionColor = tcell.Color179
	groundColor  = tcell.ColorDefault
)

// Colour tags for tview's dynamic markup. A tag is the only way to colour part of
// a line inside a text view, so the palette exists twice - once as a colour and
// once as a tag. They must agree.
const (
	inkTag     = "[#d0d0d0]"
	dimTag     = "[#8a8a8a]"
	markTag    = "[#d7af5f]"
	passTag    = "[#87af87]"
	flagTag    = "[#d78787]"
	resetTag   = "[-:-:-]"
	boldOn     = "[::b]"
	boldOff    = "[::-]"
	titleTag   = "[#d0d0d0::b]"
	commandTag = "[#87af87]"
)

// severityTag expresses weight with tone, not five accents - the same restraint
// the HTML viewer keeps.
func severityTag(severity string) string {
	switch severity {
	case "CRITICAL":
		return "[#d78787::b]"
	case "HIGH":
		return flagTag
	case "MEDIUM":
		return markTag
	case "LOW":
		return "[#a9a9a9]"
	default:
		return dimTag
	}
}
