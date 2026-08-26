// The window builds the exact argument list it will run, shows it, and runs it.
// Which passes run is chosen by ticking tools in the panel; the tools shown, their
// grouping and the model list all come from the engine (doctor --json, models), so
// nothing here is a hardcoded copy that could drift from what actually runs.

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

// Canonical order per mode, and which of those the tab lets you tick. The domain
// tab ticks the passes it fans out plus katana; its discovery tools are the
// pipeline, shown but not toggled.
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
  minsev: $("minsev"), command: $("command"), run: $("run"), status: $("status"),
  log: $("log"), reports: $("reports"), tools: $("tools"), toolprog: $("toolprog"),
};

const MODES = {
  folder: { label: "Project folder", placeholder: "/path/to/project", hint: "The folder to scan on this machine." },
  url: { label: "Address", placeholder: "https://staging.example.com", hint: "One live http/https address." },
  domain: { label: "Domain", placeholder: "example.com", hint: "A domain: its live hosts are discovered, then each is scanned." },
};

// tabMode maps the UI tab to the engine's mode name (the URL tab is "address").
function tabMode() { return state.mode === "url" ? "address" : state.mode; }
function useSet() { return state.use[tabMode()]; }

// installed reports whether a tool's binary is present, from doctor.
function installed(name) {
  const tool = inventory.find((t) => t.name === name);
  return tool ? tool.found : false;
}

// aiSelected is whether this tab's AI pass is ticked (so the model field shows).
function aiSelected() {
  const pass = AI_PASS[tabMode()];
  return pass && useSet().has(pass);
}

// toolsFlag turns the ticked set into the fewest, clearest flags: nothing when it
// is the default, --no-ai / --no-llm for the one common subtraction, else an
// explicit list.
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
  // domain: only the three passes go through --passes; katana is --crawl.
  const passes = chosen.filter((t) => t !== "katana");
  const passDef = def.filter((t) => t !== "katana");
  const passSame = passes.length === passDef.length && passes.every((t) => passDef.includes(t));
  return passSame ? [] : ["--passes", passes.join(",") || "none"];
}

// argv is the single source of truth for both the shown command and the run.
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
    if (min) a.push("--min-severity", min);
    a.push("--events");
    return a.filter(Boolean);
  }
  // domain → perimeter
  const a = ["perimeter", target];
  if (els.authorized.checked) a.push("--i-am-authorized");
  if (els.netactive.checked) a.push("--net-active");
  if (useSet().has("katana")) a.push("--crawl");
  a.push(...toolsFlag());
  return a.filter(Boolean);
}

function splitList(text) {
  return text.split(",").map((s) => s.trim()).filter(Boolean);
}

function refresh() {
  const shown = argv().filter((x) => x !== "--events");
  els.command.textContent = "whatsrisky " + shown.join(" ");
  els.modelField.hidden = !aiSelected();
  const needsAuth = state.mode !== "folder";
  const missingTarget = !els.target.value.trim();
  const missingAuth = needsAuth && !els.authorized.checked;
  els.run.disabled = missingTarget || missingAuth;
  els.run.textContent = missingAuth ? "Confirm authorization to run" : "Run scan";
}

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll("#modes button").forEach((b) => {
    b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
  });
  document.querySelectorAll("[data-for]").forEach((box) => {
    box.hidden = !box.dataset.for.split(" ").includes(mode);
  });
  els.targetLabel.textContent = MODES[mode].label;
  els.target.placeholder = MODES[mode].placeholder;
  els.targetHint.textContent = MODES[mode].hint;
  renderTools();
  refresh();
}

async function loadModels() {
  try {
    models = JSON.parse(await invoke("models"));
  } catch (err) {
    models = {};
  }
  // The folder and address AI passes use claude-cli by default; offer its models.
  const names = models["claude-cli"] || [];
  els.modelList.textContent = "";
  names.forEach((name) => els.modelList.append(el("option", null, name)));
}

async function loadDoctor() {
  els.tools.textContent = "loading…";
  try {
    inventory = JSON.parse(await invoke("doctor"));
  } catch (err) {
    els.tools.textContent = "could not read tool status: " + err;
    return;
  }
  renderTools();
}

function renderTools() {
  if (!inventory.length) return;
  els.tools.textContent = "";
  const mode = tabMode();
  const shown = inventory.filter((t) => (t.modes || []).includes(mode));
  if (!shown.length) {
    els.tools.append(el("div", "covers", "no external tools for this mode"));
    return;
  }
  shown.forEach((tool) => {
    const row = el("div", "tool");
    const selectable = SELECTABLE[mode].includes(tool.name);

    if (selectable && tool.found) {
      const box = el("input");
      box.type = "checkbox";
      box.checked = useSet().has(tool.name);
      box.addEventListener("change", () => {
        if (box.checked) useSet().add(tool.name); else useSet().delete(tool.name);
        refresh();
      });
      row.append(box);
    } else {
      const dot = el("span", "dot " + (tool.found ? "yes" : "no"));
      row.append(dot);
    }

    row.append(el("span", "name", tool.name));
    row.append(el("span", "covers", tool.found ? (tool.version || "installed") : (tool.covers || "")));

    if (!tool.found && tool.install) {
      const button = el("button", null, "Install");
      button.type = "button";
      button.addEventListener("click", () => installTool(tool.name, button));
      row.append(button);
    } else if (!tool.found) {
      row.append(el("span", "covers", "manual: " + (tool.hint || "")));
    }
    els.tools.append(row);
  });
}

async function installTool(name, button) {
  button.disabled = true;
  button.textContent = "installing…";
  line("installing " + name + "…", "progress");
  try {
    await invoke("install_tool", { name });
  } catch (err) {
    button.disabled = false;
    button.textContent = "Install";
    line("install failed: " + err, "progress");
  }
}

function line(text, stream) {
  const div = el("div", stream === "progress" ? "progress" : "out", text);
  els.log.append(div);
  els.log.scrollTop = els.log.scrollHeight;
}

async function run() {
  els.log.textContent = "";
  els.reports.textContent = "";
  els.status.textContent = "";
  els.status.className = "status";
  els.toolprog.textContent = "";
  progress.clear();
  els.run.disabled = true;
  const args = argv();
  line("whatsrisky " + args.filter((x) => x !== "--events").join(" "), "out");
  try {
    await invoke("run_scan", { args });
  } catch (err) {
    els.status.textContent = String(err);
    els.status.className = "status bad";
    refresh();
  }
}

function handleEvent(ev) {
  if (ev.kind === "info" && ev.tools) {
    progress.clear();
    ev.tools.forEach((t) => progress.set(t, { status: "pending", detail: "" }));
    renderProgress();
  } else if (ev.kind === "tool_start") {
    progress.set(ev.tool, { status: "running", detail: "" });
    renderProgress();
  } else if (ev.kind === "tool_progress") {
    const row = progress.get(ev.tool) || { status: "running" };
    row.detail = ev.message || "";
    progress.set(ev.tool, row);
    renderProgress();
  } else if (ev.kind === "tool_done") {
    progress.set(ev.tool, {
      status: ev.status === "ok" ? "ok" : "bad",
      took: ev.duration_s || 0,
      detail: ev.status === "ok" ? (ev.findings || 0) + " finding(s)" : ev.status,
    });
    renderProgress();
  }
}

function renderProgress() {
  els.toolprog.textContent = "";
  progress.forEach((row, tool) => {
    const prow = el("div", "prow");
    prow.append(el("span", "st " + (row.status === "pending" ? "" : row.status), row.status));
    prow.append(el("span", "nm", tool));
    prow.append(el("span", "detail", row.detail || ""));
    if (row.took != null) prow.append(el("span", "took", Math.round(row.took) + "s"));
    els.toolprog.append(prow);
  });
}

function showReports(reports) {
  els.reports.textContent = "";
  reports.filter((p) => /\.html$/.test(p)).forEach((path) => {
    const button = el("button", null, "Open report — " + path.split("/").pop());
    button.type = "button";
    button.addEventListener("click", () => invoke("open_report", { path }));
    els.reports.append(button);
  });
}

function wire() {
  document.querySelectorAll("#modes button").forEach((b) => {
    b.addEventListener("click", () => setMode(b.dataset.mode));
  });
  [els.target, els.authorized, els.netactive, els.exclude, els.model, els.minsev]
    .forEach((e) => { e.addEventListener("input", refresh); e.addEventListener("change", refresh); });
  els.run.addEventListener("click", run);

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
    if (error) {
      els.status.textContent = error; els.status.className = "status bad";
    } else if (code === 0 || code === 2) {
      els.status.textContent = code === 2 ? "Finished — findings at or above the fail-on threshold." : "Finished.";
      els.status.className = "status ok";
      showReports(reports || []);
    } else {
      els.status.textContent = "The scan exited with code " + code + ".";
      els.status.className = "status bad";
    }
    refresh();
  });

  setMode("folder");
  loadModels();
  loadDoctor();
}

wire();
