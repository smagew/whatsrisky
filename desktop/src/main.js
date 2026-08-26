// The window builds the exact argument list it will run, shows it, and runs it.
// The command on screen is not a mirror of what happens — it is what happens — so
// it can never drift from the scan, the way the CLI and the TUI must be kept in
// step by hand.

const tauri = window.__TAURI__ || {};
const invoke = tauri.core ? tauri.core.invoke : async () => {};
const listen = tauri.event ? tauri.event.listen : async () => () => {};

const state = { mode: "folder" };

const $ = (id) => document.getElementById(id);
const els = {
  target: $("target"), targetLabel: $("targetLabel"), targetHint: $("targetHint"),
  noai: $("noai"), authorized: $("authorized"), netactive: $("netactive"),
  nollm: $("nollm"), crawl: $("crawl"), minsev: $("minsev"),
  command: $("command"), run: $("run"), status: $("status"),
  log: $("log"), reports: $("reports"),
};

const MODES = {
  folder: { label: "Project folder", placeholder: "/path/to/project", hint: "The folder to scan on this machine." },
  url:    { label: "Address", placeholder: "https://staging.example.com", hint: "One live http/https address." },
  domain: { label: "Domain", placeholder: "example.com", hint: "A domain: its live hosts are discovered, then each is scanned." },
};

// argv is the single source of truth for both the shown command and the run.
function argv() {
  const target = els.target.value.trim();
  const min = els.minsev.value;
  if (state.mode === "folder") {
    const a = [target];
    if (els.noai.checked) a.push("--no-ai");
    if (min) a.push("--min-severity", min);
    return a.filter(Boolean);
  }
  if (state.mode === "url") {
    const a = [target];
    if (els.authorized.checked) a.push("--i-am-authorized");
    if (els.netactive.checked) a.push("--net-active");
    if (els.nollm.checked) a.push("--no-llm");
    if (min) a.push("--min-severity", min);
    return a.filter(Boolean);
  }
  // domain
  const a = ["perimeter", target];
  if (els.authorized.checked) a.push("--i-am-authorized");
  if (els.netactive.checked) a.push("--net-active");
  if (els.crawl.checked) a.push("--crawl");
  return a.filter(Boolean);
}

function refresh() {
  const a = argv();
  els.command.textContent = "whatsrisky " + a.join(" ");
  // A network or domain scan cannot run unauthorized; the button says so.
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
  refresh();
}

function line(text, stream) {
  const div = document.createElement("div");
  div.className = stream === "progress" ? "progress" : "out";
  div.textContent = text;
  els.log.append(div);
  els.log.scrollTop = els.log.scrollHeight;
}

async function run() {
  els.log.textContent = "";
  els.reports.textContent = "";
  els.status.textContent = "";
  els.status.className = "status";
  els.run.disabled = true;
  const args = argv();
  line("whatsrisky " + args.join(" "), "out");
  try {
    await invoke("run_scan", { args });
  } catch (err) {
    els.status.textContent = String(err);
    els.status.className = "status bad";
    refresh();
  }
}

function showReports(reports) {
  els.reports.textContent = "";
  reports.filter((p) => /\.html$/.test(p)).forEach((path) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Open report — " + path.split("/").pop();
    button.addEventListener("click", () => invoke("open_report", { path }));
    els.reports.append(button);
  });
}

function wire() {
  document.querySelectorAll("#modes button").forEach((b) => {
    b.addEventListener("click", () => setMode(b.dataset.mode));
  });
  [els.target, els.noai, els.authorized, els.netactive, els.nollm, els.crawl, els.minsev]
    .forEach((el) => { el.addEventListener("input", refresh); el.addEventListener("change", refresh); });
  els.run.addEventListener("click", run);

  listen("scan-line", (event) => line(event.payload.text, event.payload.stream));
  listen("scan-done", (event) => {
    const { code, reports, error } = event.payload;
    if (error) {
      els.status.textContent = error;
      els.status.className = "status bad";
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
}

wire();
