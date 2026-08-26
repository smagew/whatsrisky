# whatsrisky desktop

A small [Tauri](https://tauri.app) window over the `whatsrisky` binary. It owns no
scanning logic: it builds the exact command it will run — a folder scan, an address
scan, or a whole-domain perimeter scan — shows that command, runs the binary,
streams its progress, and opens the report the binary wrote (the same self-contained
HTML viewer the CLI produces).

Tauri was chosen over Electron to keep the footprint small: a system webview and a
thin Rust shell, megabytes rather than a bundled Chromium — in the spirit of the
single Go binary the engine already is.

## Run it

You need the `whatsrisky` binary on your `PATH` (or set `WHATSRISKY_BIN` to its
path), plus Node and the Rust toolchain.

```bash
cd desktop
npm install
npm run dev      # a dev window
npm run build    # a packaged app
```

## How it fits

- The Rust shell (`src-tauri/src/lib.rs`) exposes two commands: `run_scan`, which
  spawns the binary and streams its output as events, and `open_report`, which
  opens a finished report in the OS default handler.
- The window (`src/`) is plain HTML/CSS/JS — no framework, no build step — using the
  report viewer's palette so the two look like one tool.
- The command shown on screen **is** the argument list that runs, so it cannot drift
  from the scan, the way the CLI and the TUI have to be kept in step by hand.

## Status

The Rust shell compiles against Tauri v2 (`cargo check`) and the frontend is plain,
checked JS. It has not been launched in this environment (no display); run the dev
window above to use it. A native folder picker, live report embedding, and the
richer perimeter controls (per-pass toggles, wordlists) are the next steps.
