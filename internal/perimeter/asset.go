// Package perimeter turns a domain into the live web assets under it, so a scan
// can cover a whole estate rather than one address. It is an orchestrator: it
// discovers, then hands each asset to the same per-target passes the single-target
// scan uses.
package perimeter

import "github.com/smagew/whatsrisky/internal/model"

// Asset is the report's asset type, used throughout the perimeter package so the
// inventory it builds is exactly what the report carries.
type Asset = model.Asset
