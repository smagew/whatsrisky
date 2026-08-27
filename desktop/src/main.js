// The window builds the exact argument list it will run, shows it, and runs it.
// Which passes run is chosen by ticking tools; the tools, their grouping and the
// model list all come from the engine, so nothing here is a hardcoded copy that
// could drift from what actually runs.

const tauri = window.__TAURI__ || {};
const invoke = tauri.core ? tauri.core.invoke : async () => {};
const listen = tauri.event ? tauri.event.listen : async () => () => {};

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};

const SELECTABLE = {
  folder: ["semgrep", "trivy", "gitleaks", "ai"],
  address: ["surface", "testssl", "nuclei", "zap", "ffuf", "llm-recon"],
  domain: ["surface", "testssl", "nuclei", "katana"],
};
const DEFAULT_USE = {
  folder: ["semgrep", "trivy", "gitleaks", "ai"],
  address: ["surface", "testssl", "nuclei", "llm-recon"],
  domain: ["surface", "testssl", "nuclei"],
};
const AI_PASS = { folder: "ai", address: "llm-recon", domain: "" };
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const state = {
  mode: "folder",
  use: {
    folder: new Set(DEFAULT_USE.folder),
    address: new Set(DEFAULT_USE.address),
    domain: new Set(DEFAULT_USE.domain),
  },
};
let inventory = [];
let models = {};
const progress = new Map();

const els = {
  target: $("target"), targetLabel: $("targetLabel"), targetHint: $("targetHint"),
  authorized: $("authorized"), netactive: $("netactive"),
  exclude: $("exclude"), model: $("model"), modelField: $("modelField"), modelList: $("modelList"),
  wordlist: $("wordlist"), wordlistField: $("wordlistField"),
  minsev: $("minsev"), command: $("command"), run: $("run"), status: $("status"),
  log: $("log"), reports: $("reports"), tools: $("tools"), toolprog: $("toolprog"),
  bar: $("bar"), barFill: $("barFill"), stop: $("stop"), divider: $("divider"),
  modedesc: $("modedesc"), theme: $("theme"),
  verdict: $("verdict"), verdictName: $("verdictName"), verdictSay: $("verdictSay"),
  verdictRisk: $("verdictRisk"), tallies: $("tallies"),
};

const MODES = {
  folder: {
    label: "Project folder", placeholder: "/path/to/project", hint: "The folder to scan on this machine.",
    desc: "Reads the source code in a folder — static analysis for risky code, dependency CVEs, secrets in the tree and git history, and an optional AI review. Nothing leaves the machine unless you tick the AI pass.",
  },
  url: {
    label: "Address", placeholder: "https://staging.example.com", hint: "One live http/https address.",
    desc: "Scans one running address: its TLS and security headers, templates for known vulnerabilities, and an optional LLM look for weak spots. Observational by default — attacks need --net-active.",
  },
  domain: {
    label: "Domain", placeholder: "example.com", hint: "A domain: its live hosts are discovered, then each is scanned.",
    desc: "Maps the whole estate under a domain — finds the subdomains, sees which are alive, screenshots them — then runs the observational passes across every one, into one report.",
  },
};

function tabMode() { return state.mode === "url" ? "address" : state.mode; }
function useSet() { return state.use[tabMode()]; }
function installed(name) { const t = inventory.find((x) => x.name === name); return t ? t.found : false; }
function aiSelected() { const p = AI_PASS[tabMode()]; return p && useSet().has(p); }
function ffufSelected() { return tabMode() === "address" && useSet().has("ffuf"); }

function toolsFlag() {
  const mode = tabMode();
  const chosen = SELECTABLE[mode].filter((t) => useSet().has(t));
  const def = DEFAULT_USE[mode];
  const same = chosen.length === def.length && chosen.every((t) => def.includes(t));
  if (same) return [];
  if (mode === "folder") {
    const withoutAI = def.filter((t) => t !== "ai");
    if (chosen.length === withoutAI.length && chosen.every((t) => withoutAI.includes(t))) return ["--no-ai"];
    return chosen.length ? ["--tools", chosen.join(",")] : ["--tools", "none"];
  }
  if (mode === "address") {
    const withoutLLM = def.filter((t) => t !== "llm-recon");
    if (chosen.length === withoutLLM.length && chosen.every((t) => withoutLLM.includes(t))) return ["--no-llm"];
    return chosen.length ? ["--passes", chosen.join(",")] : ["--passes", "none"];
  }
  const passes = chosen.filter((t) => t !== "katana");
  const passDef = def.filter((t) => t !== "katana");
  const passSame = passes.length === passDef.length && passes.every((t) => passDef.includes(t));
  return passSame ? [] : ["--passes", passes.join(",") || "none"];
}

function argv() {
  const target = els.target.value.trim();
  const min = els.minsev.value;
  const model = els.model.value.trim();
  if (state.mode === "folder") {
    const a = [target, ...toolsFlag()];
    splitList(els.exclude.value).forEach((p) => a.push("--exclude", p));
    if (aiSelected() && model) a.push("--model", model);
    if (min) a.push("--min-severity", min);
    a.push("--events");
    return a.filter(Boolean);
  }
  if (state.mode === "url") {
    const a = [target];
    if (els.authorized.checked) a.push("--i-am-authorized");
    if (els.netactive.checked) a.push("--net-active");
    a.push(...toolsFlag());
    if (aiSelected() && model) a.push("--model", model);
    if (ffufSelected() && els.wordlist.value.trim()) a.push("--wordlist", els.wordlist.value.trim());
    if (min) a.push("--min-severity", min);
    a.push("--events");
    return a.filter(Boolean);
  }
  const a = ["perimeter", target];
  if (els.authorized.checked) a.push("--i-am-authorized");
  if (els.netactive.checked) a.push("--net-active");
  if (useSet().has("katana")) a.push("--crawl");
  a.push(...toolsFlag());
  return a.filter(Boolean);
}

function splitList(text) { return text.split(",").map((s) => s.trim()).filter(Boolean); }

// renderCommand shows the argv as it will run, program and flags coloured, so the
// contract between the window and the CLI reads at a glance.
function renderCommand(args) {
  els.command.textContent = "";
  els.command.append(el("span", "p", "whatsrisky"));
  args.forEach((tok) => {
    els.command.append(document.createTextNode(" "));
    els.command.append(el("span", tok.startsWith("-") ? "f" : "", tok));
  });
}

function refresh() {
  const shown = argv().filter((x) => x !== "--events");
  renderCommand(shown);
  els.modelField.hidden = !aiSelected();
  els.wordlistField.hidden = !ffufSelected();
  const needsAuth = state.mode !== "folder";
  const missingTarget = !els.target.value.trim();
  const missingAuth = needsAuth && !els.authorized.checked;
  els.run.disabled = missingTarget || missingAuth;
  els.run.textContent = missingAuth ? "confirm authorization" : "▶ run scan";
}

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll("#modes .mode").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === mode)));
  document.querySelectorAll("[data-for]").forEach((box) => { box.hidden = !box.dataset.for.split(" ").includes(mode); });
  els.targetLabel.textContent = MODES[mode].label;
  els.target.placeholder = MODES[mode].placeholder;
  els.targetHint.textContent = MODES[mode].hint;
  els.modedesc.textContent = MODES[mode].desc;
  renderTools();
  refresh();
}

// --- theme: default dark, manual override on top, remembered ---------
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  els.theme.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.t === t));
  try { localStorage.setItem("wr-theme", t); } catch (e) { /* private mode */ }
}
function initTheme() {
  let t = "dark";
  try { t = localStorage.getItem("wr-theme") || "dark"; } catch (e) { /* private mode */ }
  applyTheme(t);
  els.theme.addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (b) applyTheme(b.dataset.t);
  });
}

async function loadModels() {
  try { models = JSON.parse(await invoke("models")); } catch (e) { models = {}; }
  const names = models["claude-cli"] || [];
  els.modelList.textContent = "";
  names.forEach((n) => els.modelList.append(el("option", null, n)));
}

async function loadDoctor() {
  els.tools.textContent = "loading…";
  try { inventory = JSON.parse(await invoke("doctor")); }
  catch (err) { els.tools.textContent = "could not read tool status: " + err; return; }
  renderTools();
}

function renderTools() {
  if (!inventory.length) return;
  els.tools.textContent = "";
  const mode = tabMode();
  const shown = inventory.filter((t) => (t.modes || []).includes(mode));
  if (!shown.length) { els.tools.append(el("div", "covers", "no external tools for this mode")); return; }
  shown.forEach((tool) => {
    const wrap = el("div", "toolwrap");
    const row = el("div", "tool");
    const selectable = SELECTABLE[mode].includes(tool.name);
    if (selectable && tool.found) {
      const box = el("input"); box.type = "checkbox"; box.checked = useSet().has(tool.name);
      box.addEventListener("change", () => { box.checked ? useSet().add(tool.name) : useSet().delete(tool.name); refresh(); });
      row.append(box);
    } else {
      row.append(el("span", "dot " + (tool.found ? "yes" : "no")));
    }
    row.append(el("span", "name", tool.name));
    const covers = el("span", "covers", tool.covers || "");
    if (tool.found && tool.version) covers.append(el("span", "ver", "  · " + tool.version));
    row.append(covers);
    if (!tool.found && tool.install) {
      const button = el("button", "install", "Install"); button.type = "button";
      button.addEventListener("click", () => installTool(tool.name, button));
      row.append(button);
    } else if (!tool.found) {
      row.append(el("span", "not-installed", "not installed"));
    }
    if (tool.detail) {
      const detail = el("div", "tooldetail", tool.detail); detail.hidden = true;
      const more = el("button", "more", "more"); more.type = "button";
      more.addEventListener("click", () => { detail.hidden = !detail.hidden; more.textContent = detail.hidden ? "more" : "less"; });
      row.append(more); wrap.append(row); wrap.append(detail);
    } else {
      wrap.append(row);
    }
    if (!tool.found && !tool.install && tool.hint) wrap.append(el("div", "toolnote", "get it: " + cleanHint(tool.hint)));
    els.tools.append(wrap);
  });
}

function cleanHint(hint) { return hint.replace(/^`[^`]+`\s*not found in PATH[.:]?\s*(Install:\s*)?/i, "").trim(); }

async function installTool(name, button) {
  button.disabled = true; button.textContent = "installing…";
  line("installing " + name + "…", "progress");
  try { await invoke("install_tool", { name }); }
  catch (err) { button.disabled = false; button.textContent = "Install"; line("install failed: " + err, "progress"); }
}

function line(text, stream) {
  const div = el("div", stream === "progress" ? "progress" : "out", text);
  els.log.append(div); els.log.scrollTop = els.log.scrollHeight;
}

async function run() {
  els.log.textContent = ""; els.reports.textContent = "";
  els.status.textContent = ""; els.status.className = "status";
  els.toolprog.textContent = ""; progress.clear();
  els.verdict.hidden = true;
  els.barFill.style.width = "0"; els.bar.hidden = true;
  els.run.disabled = true; els.stop.hidden = false;
  const args = argv();
  line("whatsrisky " + args.filter((x) => x !== "--events").join(" "), "out");
  try { await invoke("run_scan", { args }); }
  catch (err) { els.status.textContent = String(err); els.status.className = "status bad"; els.stop.hidden = true; refresh(); }
}

function handleEvent(ev) {
  if (ev.kind === "info" && ev.tools) {
    progress.clear(); ev.tools.forEach((t) => progress.set(t, { status: "pending" }));
    els.bar.hidden = false; renderProgress();
  } else if (ev.kind === "tool_start") {
    progress.set(ev.tool, { status: "running" }); renderProgress();
  } else if (ev.kind === "tool_progress") {
    const row = progress.get(ev.tool) || { status: "running" }; row.detail = ev.message || "";
    progress.set(ev.tool, row); renderProgress();
  } else if (ev.kind === "tool_done") {
    const ok = ev.status === "ok";
    progress.set(ev.tool, { status: ok ? "ok" : "bad", took: ev.duration_s || 0,
      detail: ok ? (ev.findings || 0) + " finding(s)" : "", reason: ok ? "" : (ev.message || ev.status || "") });
    renderProgress();
  } else if (ev.kind === "summary") {
    showVerdict(ev);
  } else if (ev.kind === "report") {
    finish(ev.paths || []);
  }
}

// showVerdict gives the result weight: the risk word, the phrase, and the tallies,
// coloured by the worst severity present.
function showVerdict(ev) {
  const counts = ev.counts || {};
  const worst = SEVS.find((s) => (counts[s] || 0) > 0);
  const sevColor = worst ? `var(--${severityToken(worst)})` : "var(--pass)";
  els.verdict.style.setProperty("--sev", sevColor);
  els.verdict.hidden = false;
  els.verdictName.textContent = els.target.value.trim() || "scan";
  const parts = (ev.verdict || "").split(/\s+[–-]\s+/);
  els.verdictRisk.textContent = (parts[0] || "").replace(/\s*RISK$/i, "").trim() || "DONE";
  els.verdictRisk.style.color = sevColor;
  els.verdictSay.textContent = parts[1] || (ev.findings ? ev.findings + " finding(s)" : "nothing found");
  els.tallies.textContent = "";
  SEVS.forEach((s) => {
    const tile = el("div", "tally " + s);
    tile.append(el("div", "n", String(counts[s] || 0)));
    tile.append(el("div", "l", s.slice(0, 4).toLowerCase()));
    els.tallies.append(tile);
  });
}

function severityToken(sev) {
  if (sev === "CRITICAL" || sev === "HIGH") return "flag";
  if (sev === "MEDIUM") return "caution";
  return "ink-3";
}

function finish(reports) {
  progress.forEach((row) => { if (row.status === "running" || row.status === "pending") row.status = "ok"; });
  renderProgress();
  els.barFill.style.width = "100%"; els.stop.hidden = true;
  if (reports && reports.length) showReports(reports);
  if (!els.status.textContent) { els.status.textContent = "finished"; els.status.className = "status ok"; }
  refresh();
}

function renderProgress() {
  els.toolprog.textContent = "";
  let done = 0; const total = progress.size;
  progress.forEach((row, tool) => {
    if (row.status === "ok" || row.status === "bad") done++;
    const prow = el("div", "prow");
    if (row.status === "running") prow.append(el("span", "spin"));
    else prow.append(el("span", "st " + row.status, row.status === "ok" ? "▪" : row.status === "bad" ? "✗" : "·"));
    prow.append(el("span", "nm", tool));
    prow.append(el("span", row.reason ? "reason" : "detail", row.reason || row.detail || ""));
    if (row.took != null) prow.append(el("span", "took", Math.round(row.took) + "s"));
    els.toolprog.append(prow);
  });
  if (total > 0) els.barFill.style.width = Math.round((done / total) * 100) + "%";
}

function showReports(reports) {
  els.reports.textContent = "";
  reports.filter((p) => /\.html$/.test(p)).forEach((path) => {
    const button = el("button", null, "Open report — " + path.split("/").pop()); button.type = "button";
    button.addEventListener("click", () => invoke("open_report", { path }));
    els.reports.append(button);
  });
}

function wireDivider() {
  let saved = null; try { saved = localStorage.getItem("wr-left"); } catch (e) { /* */ }
  if (saved) document.documentElement.style.setProperty("--left", saved);
  let dragging = false;
  els.divider.addEventListener("mousedown", (e) => { dragging = true; e.preventDefault(); document.body.style.userSelect = "none"; });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const rect = els.divider.parentElement.getBoundingClientRect();
    let pct = ((e.clientX - rect.left) / rect.width) * 100;
    pct = Math.max(25, Math.min(75, pct));
    const value = pct.toFixed(1) + "%";
    document.documentElement.style.setProperty("--left", value);
    try { localStorage.setItem("wr-left", value); } catch (e2) { /* */ }
  });
  window.addEventListener("mouseup", () => { dragging = false; document.body.style.userSelect = ""; });
}

function wire() {
  initTheme();
  document.querySelectorAll("#modes .mode").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  [els.target, els.authorized, els.netactive, els.exclude, els.model, els.wordlist, els.minsev]
    .forEach((e) => { e.addEventListener("input", refresh); e.addEventListener("change", refresh); });
  els.run.addEventListener("click", run);
  els.stop.addEventListener("click", () => {
    els.stop.disabled = true;
    invoke("cancel_scan").finally(() => {
      els.stop.disabled = false; els.stop.hidden = true;
      els.status.textContent = "stopped"; els.status.className = "status bad"; refresh();
    });
  });
  wireDivider();

  listen("scan-line", (event) => {
    const text = event.payload.text;
    if (text.startsWith("EVENT ")) { handleEvent(JSON.parse(text.slice(6))); return; }
    line(text, event.payload.stream);
  });
  listen("install-line", (event) => line(event.payload[0] + ": " + event.payload[1], "progress"));
  listen("install-done", (event) => {
    const [name, code] = event.payload;
    line(name + (code === 0 ? " installed" : " install exited " + code), "progress");
    loadDoctor();
  });
  listen("scan-done", (event) => {
    const { code, reports, error } = event.payload;
    if (error) { els.status.textContent = error; els.status.className = "status bad"; els.stop.hidden = true; }
    else if (code === 0 || code === 2) { finish(reports || []); }
    else { els.status.textContent = "exited " + code; els.status.className = "status bad"; els.stop.hidden = true; }
    refresh();
  });

  setMode("folder");
  loadModels();
  loadDoctor();
}

wire();
