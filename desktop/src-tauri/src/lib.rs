// The desktop shell. It owns no scanning logic: it runs the whatsrisky binary,
// streams its output to the window, and opens the report the binary wrote. The
// engine stays the single source of truth, exactly as the CLI and the TUI use it.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

// A line of scanner output, tagged with the stream it came from so the window can
// show progress and errors differently.
#[derive(Clone, Serialize)]
struct Line {
    stream: String,
    text: String,
}

// The result of a run: the exit code and the report files the binary reported
// writing, parsed from its "report <path>" lines.
#[derive(Clone, Serialize)]
struct Done {
    code: i32,
    reports: Vec<String>,
    error: Option<String>,
}

// binary resolves the whatsrisky executable: an explicit path wins, then the
// WHATSRISKY_BIN environment variable, then whatever is on PATH.
fn binary(explicit: &Option<String>) -> String {
    if let Some(path) = explicit {
        if !path.trim().is_empty() {
            return path.clone();
        }
    }
    if let Ok(env) = std::env::var("WHATSRISKY_BIN") {
        if !env.trim().is_empty() {
            return env;
        }
    }
    "whatsrisky".to_string()
}

// augmentedPath is PATH with the usual install locations prepended, because a
// macOS GUI app inherits a minimal PATH: without this, a tool installed by
// Homebrew (/opt/homebrew/bin, /usr/local/bin) or by `go install` (~/go/bin) is
// present on disk but invisible to the scan the window launches.
fn augmented_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs = vec![
        format!("{home}/go/bin"),
        format!("{home}/.local/bin"),
        "/opt/homebrew/bin".to_string(),
        "/opt/homebrew/sbin".to_string(),
        "/usr/local/bin".to_string(),
        "/usr/local/sbin".to_string(),
    ];
    if let Ok(existing) = std::env::var("PATH") {
        dirs.push(existing);
    }
    dirs.join(":")
}

// tool builds a Command for the whatsrisky binary (or a helper) with the augmented
// PATH, so everything the window spawns can find what is installed.
fn tool(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env("PATH", augmented_path());
    command
}

// run_scan launches the binary with the given arguments and streams its output to
// the window as `scan-line` events, then a single `scan-done`. It returns
// immediately; the work happens on a thread so the UI never blocks.
#[tauri::command]
fn run_scan(app: AppHandle, args: Vec<String>, bin: Option<String>) {
    let program = binary(&bin);
    thread::spawn(move || {
        let mut child = match tool(&program)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                let _ = app.emit(
                    "scan-done",
                    Done {
                        code: -1,
                        reports: vec![],
                        error: Some(format!("could not start {program}: {err}")),
                    },
                );
                return;
            }
        };

        let mut reports: Vec<String> = Vec::new();

        // stderr on its own thread; whatsrisky writes progress there.
        if let Some(stderr) = child.stderr.take() {
            let app = app.clone();
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let _ = app.emit(
                        "scan-line",
                        Line {
                            stream: "progress".into(),
                            text: line,
                        },
                    );
                }
            });
        }

        // stdout on this thread; the report paths are printed there.
        if let Some(stdout) = child.stdout.take() {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(path) = line.strip_prefix("report ") {
                    reports.push(path.trim().to_string());
                }
                let _ = app.emit(
                    "scan-line",
                    Line {
                        stream: "out".into(),
                        text: line,
                    },
                );
            }
        }

        let code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
        let _ = app.emit(
            "scan-done",
            Done {
                code,
                reports,
                error: None,
            },
        );
    });
}

// doctor returns the tool inventory as JSON, so the window can show what will run
// and offer to install what is missing.
#[tauri::command]
fn doctor(bin: Option<String>) -> Result<String, String> {
    let out = tool(&binary(&bin))
        .args(["doctor", "--json"])
        .output()
        .map_err(|err| err.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// models returns the AI models per provider as JSON, for the model picker.
#[tauri::command]
fn models(bin: Option<String>) -> Result<String, String> {
    let out = tool(&binary(&bin))
        .arg("models")
        .output()
        .map_err(|err| err.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// install_tool installs one named tool, streaming the package manager's output to
// the window, then reports done. The engine owns which command to run.
#[tauri::command]
fn install_tool(app: AppHandle, name: String, bin: Option<String>) {
    let program = binary(&bin);
    thread::spawn(move || {
        let mut child = match tool(&program)
            .args(["doctor", "--install-tool", &name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                let _ = app.emit("install-done", (name.clone(), -1, format!("{err}")));
                return;
            }
        };
        if let Some(stderr) = child.stderr.take() {
            let app = app.clone();
            let name = name.clone();
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let _ = app.emit("install-line", (name.clone(), line));
                }
            });
        }
        if let Some(stdout) = child.stdout.take() {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = app.emit("install-line", (name.clone(), line));
            }
        }
        let code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
        let _ = app.emit("install-done", (name, code, String::new()));
    });
}

// open_report opens a finished report in the operating system's default handler,
// so the full HTML viewer - the same one the CLI writes - is what the user reads.
#[tauri::command]
fn open_report(path: String) -> Result<(), String> {
    let result = if cfg!(target_os = "macos") {
        Command::new("open").arg(&path).spawn()
    } else if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "start", "", &path]).spawn()
    } else {
        Command::new("xdg-open").arg(&path).spawn()
    };
    result.map(|_| ()).map_err(|err| err.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_scan,
            open_report,
            doctor,
            install_tool,
            models
        ])
        .run(tauri::generate_context!())
        .expect("error while running the whatsrisky window");
}
