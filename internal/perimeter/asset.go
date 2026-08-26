// Package perimeter turns a domain into the live web assets under it, so a scan
// can cover a whole estate rather than one address. It is an orchestrator: it
// discovers, then hands each asset to the same per-target passes the single-target
// scan uses. Discovery here, the fan-out and the aggregate report on top of it.
package perimeter

// Asset is one thing found under a domain: a hostname, whether it resolved, and —
// if it answered HTTP — the URL to scan, its status and the stack it advertised.
type Asset struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips,omitempty"`
	URL    string   `json:"url,omitempty"`
	Status int      `json:"status,omitempty"`
	Title  string   `json:"title,omitempty"`
	Tech   []string `json:"tech,omitempty"`
	Alive  bool     `json:"alive"`
}
