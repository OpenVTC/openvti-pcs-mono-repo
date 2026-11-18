#!/usr/bin/env node
// Drive the VTC admin console (http://localhost:8200/admin/) headlessly, so the
// console steps of infra/README.md §3-4 can run with no person at the keyboard.
//
// It runs the real console in headless Chrome over the Chrome DevTools Protocol
// and gives it a CDP WebAuthn *virtual authenticator* as its passkey. Nothing
// server-side is bypassed: the VTC still asks for a passkey assertion bound to
// each criteria change (VTI-APV-023), and the virtual authenticator makes it,
// exactly as a platform passkey would after a touch.
//
// The passkey lives only as long as the browser, so after `claim` registers it
// its credential (private key included) is exported to
// infra/.state/console-passkey.json and re-added on every later run.
//
// No third-party packages: Node's built-in WebSocket and fetch, and the
// installed Chrome. Usage: infra/bin/console help

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// ── Paths and settings ─────────────────────────────────────────────────────

const INFRA = path.resolve(import.meta.dirname, "..", "..");
const STATE = path.join(INFRA, ".state");
const CHROME_DIR = path.join(STATE, "console-chrome");
const PROFILE = path.join(CHROME_DIR, "profile");
const PASSKEY_FILE = path.join(STATE, "console-passkey.json");
const INVITE_FILE = path.join(STATE, "vtc-admin-invite.txt");
const COOKIE_FILE = path.join(CHROME_DIR, "cookies.json");
const SIGN_COUNT_MARGIN = 1000;
const UNUSED_ANONYMOUS_TASKS = ["https://trusttasks.org/spec/auth/oob/", "https://trusttasks.org/spec/vtc/community/theme/show/"];
const BASE = (process.env.VTC_URL || "http://localhost:8200").replace(/\/$/, "");
const CHROME =
  process.env.CHROME_BIN || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const TIMEOUT = Number(process.env.CONSOLE_TIMEOUT_MS || 60_000);
const VERBOSE = process.env.CONSOLE_VERBOSE === "1";

const TASK = "https://trusttasks.org/spec/";
const T_MANIFEST = `${TASK}vtc/join-requests/manifest/0.4`;
const T_ACCEPTS_LIST = `${TASK}vtc/schemas/accepts/list/0.2`;
const T_HIDDEN_SHOW = `${TASK}vtc/vetting/hidden/show/0.1`;
const T_WHOAMI = `${TASK}auth/whoami/0.1`;
const T_JR_LIST = `${TASK}vtc/join-requests/list/0.2`;
const T_JR_SHOW = `${TASK}vtc/join-requests/show/0.1`;
const T_JR_DECIDE = `${TASK}vtc/join-requests/decide/0.1`;
const HIDDEN_NS = "org.openvtc.hidden-vetting";

const log = (...a) => console.error("[console]", ...a);
const debug = (...a) => VERBOSE && console.error("[console:debug]", ...a);

class UsageError extends Error {}

// ── Chrome + CDP ───────────────────────────────────────────────────────────

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.seq = 0;
    this.pending = new Map();
    this.handlers = new Set();
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data).toString());
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
        else p.resolve(msg.result);
      } else {
        for (const h of this.handlers) h(msg.method, msg.params);
      }
    });
    ws.addEventListener("close", () => {
      for (const p of this.pending.values()) p.reject(new Error("the browser connection closed"));
      this.pending.clear();
    });
  }
  send(method, params = {}) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(handler) {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }
}

async function until(fn, { timeout = TIMEOUT, interval = 150, what = "a condition" } = {}) {
  const deadline = Date.now() + timeout;
  let last;
  for (;;) {
    last = await fn();
    if (last) return last;
    if (Date.now() > deadline) throw new Error(`timed out after ${timeout} ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, interval));
  }
}

async function launchChrome() {
  if (!fs.existsSync(CHROME)) {
    throw new Error(`Chrome not found at ${CHROME} (set CHROME_BIN to override)`);
  }
  fs.mkdirSync(PROFILE, { recursive: true, mode: 0o700 });
  const portFile = path.join(PROFILE, "DevToolsActivePort");
  fs.rmSync(portFile, { force: true });
  const proc = spawn(
    CHROME,
    [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${PROFILE}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-extensions",
      "--password-store=basic",
      "--use-mock-keychain",
      "--window-size=1400,1100",
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  proc.stderr.on("data", (d) => {
    stderr = (stderr + d).slice(-4000);
  });
  const exited = new Promise((r) => proc.once("exit", r));
  const port = await until(
    () => {
      if (proc.exitCode !== null) {
        throw new Error(
          `Chrome exited (${proc.exitCode}) before opening its debugging port. ` +
            `Is another console run still using ${PROFILE}?\n${stderr}`,
        );
      }
      try {
        return fs.readFileSync(portFile, "utf8").split("\n")[0].trim() || null;
      } catch {
        return null;
      }
    },
    { timeout: 20_000, interval: 100, what: "Chrome's DevTools port" },
  );
  const targets = await until(
    async () => {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      return list.find((t) => t.type === "page") ?? null;
    },
    { timeout: 10_000, what: "a Chrome page target" },
  );
  const ws = new WebSocket(targets.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error("could not connect to Chrome over CDP")), {
      once: true,
    });
  });
  const close = async () => {
    try {
      ws.close();
    } catch {}
    if (proc.exitCode === null) {
      proc.kill("SIGTERM");
      await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
      if (proc.exitCode === null) proc.kill("SIGKILL");
    }
  };
  return { cdp: new Cdp(ws), close };
}

// ── In-page helpers (shadow-DOM aware: the console's dialogs are in open shadow roots) ──

const PAGE_HELPERS = String.raw`
(() => {
  if (window.__vc) return;
  const norm = (s) => (s || "").replace(/\s+/g, " ").trim();
  function roots() {
    const out = [document];
    for (let i = 0; i < out.length; i++) {
      for (const el of out[i].querySelectorAll("*")) if (el.shadowRoot) out.push(el.shadowRoot);
    }
    return out;
  }
  function all(sel) {
    const out = [];
    for (const r of roots()) out.push(...r.querySelectorAll(sel));
    return out;
  }
  function visible(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none";
  }
  // spec: { sel, text?, exact?, within? (selector of an ancestor whose text includes withinText), withinText?, any? }
  function find(spec) {
    let els = all(spec.sel);
    if (spec.text !== undefined) {
      els = els.filter((el) => {
        const t = norm(el.textContent);
        return spec.exact ? t === spec.text : t.includes(spec.text);
      });
    }
    if (spec.withinText !== undefined) {
      els = els.filter((el) => {
        const anc = el.closest(spec.within);
        return anc && norm(anc.textContent).includes(spec.withinText);
      });
    }
    if (!spec.any) els = els.filter(visible);
    return els[0] || null;
  }
  function text(sel) {
    return all(sel).filter(visible).map((el) => norm(el.textContent));
  }
  function dialogs() {
    return all('[role="dialog"]').filter(visible).map((d) => ({
      title: norm((d.querySelector("h1,h2,h3") || {}).textContent),
      message: norm((d.querySelector("p") || {}).textContent),
      buttons: [...d.querySelectorAll("button")].map((b) => norm(b.textContent)),
    }));
  }
  function state() {
    const h = (sel, t) => text(sel).some((x) => x.startsWith(t));
    if (h(".install-page h3", "Enter your claim code")) return "install-code";
    if (h(".install-page h3", "Registering passkey")) return "install-registering";
    if (h(".install-page h3", "Admin set up")) return "install-success";
    if (find({ sel: ".install-page .card.error" })) return "install-error";
    if (document.getElementById("admin-nav")) return "shell";
    if (h("h2", "Set up signing")) return "setup-signing";
    if (h("h2", "Could not check this browser")) return "signing-check-failed";
    if (h("h2", "This browser cannot sign")) return "cannot-sign";
    if (find({ sel: "button", text: "Sign in with a passkey" }) || find({ sel: "button", text: "Waiting for your passkey" })) return "login";
    return "loading";
  }
  function errors() {
    return [
      ...text('.finding.error'),
      ...text('.card.error'),
      ...text('.alert[role="alert"]'),
      ...text('.toast-error'),
    ];
  }
  window.__vc = { norm, all, find, text, visible, dialogs, state, errors };
})();
`;

class Page {
  constructor(cdp) {
    this.cdp = cdp;
    this.inflight = new Map(); // requestId -> startedAt
    this.lastActivity = Date.now();
    this.trustTasks = new Map(); // requestId -> {type}
    this.responses = []; // {type, status, body}
    this.authenticatorId = null;
    this.consoleErrors = [];
    this.limited = []; // 429s seen: {url, retryAfter, at}
    cdp.on((method, p) => this.onEvent(method, p));
  }

  rateLimitedSince(since) {
    return [...this.limited].reverse().find((l) => l.at >= since) ?? null;
  }

  // The console's session cookies are browser-session cookies, which Chrome
  // drops on exit; carrying them across runs saves a sign-in (and the VTC's
  // per-address sign-in budget) on every run. A stale one just leads to Login.
  async restoreCookies() {
    try {
      const cookies = JSON.parse(fs.readFileSync(COOKIE_FILE, "utf8"));
      if (Array.isArray(cookies) && cookies.length) {
        await this.cdp.send("Network.setCookies", {
          // By URL, not domain: a `__Host-` cookie must carry no Domain.
          cookies: cookies.map(({ name, value, path: p, secure, httpOnly, sameSite, expires }) => ({
            name,
            value,
            url: BASE + (p || "/"),
            path: p,
            secure,
            httpOnly,
            ...(sameSite ? { sameSite } : {}),
            ...(expires && expires > 0 ? { expires } : {}),
          })),
        });
      }
    } catch {}
  }

  async saveCookies() {
    const host = new URL(BASE).hostname;
    const { cookies } = await this.cdp.send("Network.getAllCookies");
    const ours = cookies.filter((c) => c.domain.replace(/^\./, "") === host);
    fs.mkdirSync(CHROME_DIR, { recursive: true });
    fs.writeFileSync(COOKIE_FILE, JSON.stringify(ours, null, 2), { mode: 0o600 });
  }

  async init() {
    const c = this.cdp;
    await c.send("Page.enable");
    await c.send("Runtime.enable");
    await c.send("Network.enable", { maxPostDataSize: 1 << 20 });
    await c.send("Page.addScriptToEvaluateOnNewDocument", { source: PAGE_HELPERS });
    // A headless page is never the focused window; without this, focus and
    // typing can silently land nowhere.
    await c.send("Emulation.setFocusEmulationEnabled", { enabled: true });
    // The VTC gives each address one small anonymous budget (a burst of 10,
    // then one call per 5 s), shared by every client on this host. The
    // sign-in page spends it on things this script never uses — the wallet
    // sign-in's out-of-band request and the community theme — so those calls
    // are dropped in the browser before they reach the VTC.
    await c.send("Fetch.enable", { patterns: [{ urlPattern: "*/v1/trust-tasks", requestStage: "Request" }] });
    await c.send("Emulation.setDeviceMetricsOverride", {
      width: 1400,
      height: 1100,
      deviceScaleFactor: 1,
      mobile: false,
    });
  }

  onEvent(method, p) {
    switch (method) {
      case "Fetch.requestPaused": {
        let type = null;
        try {
          type = JSON.parse(p.request.postData || "{}").type ?? null;
        } catch {}
        if (type && UNUSED_ANONYMOUS_TASKS.some((t) => type.startsWith(t))) {
          debug("dropped", type);
          this.cdp.send("Fetch.failRequest", { requestId: p.requestId, errorReason: "BlockedByClient" }).catch(() => {});
        } else {
          this.cdp.send("Fetch.continueRequest", { requestId: p.requestId }).catch(() => {});
        }
        break;
      }
      case "Network.requestWillBeSent": {
        this.inflight.set(p.requestId, Date.now());
        this.lastActivity = Date.now();
        const url = p.request.url;
        if (url.endsWith("/v1/trust-tasks") && p.request.method === "POST") {
          let type = null;
          try {
            type = JSON.parse(p.request.postData || "{}").type ?? null;
          } catch {}
          this.trustTasks.set(p.requestId, { type });
        }
        break;
      }
      case "Network.responseReceived": {
        const t = this.trustTasks.get(p.requestId);
        if (t) t.status = p.response.status;
        if (p.response.status === 429) {
          const h = Object.fromEntries(
            Object.entries(p.response.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
          );
          const retryAfter = Number(h["retry-after"]);
          this.limited.push({
            url: p.response.url,
            retryAfter: Number.isFinite(retryAfter) ? retryAfter : null,
            at: Date.now(),
          });
          this.cdp
            .send("Network.getResponseBody", { requestId: p.requestId })
            .then((r) => {
              const secs = JSON.parse(r.body)?.retryAfterSecs;
              if (typeof secs === "number") this.limited[this.limited.length - 1].retryAfter = secs;
            })
            .catch(() => {});
        }
        break;
      }
      case "Network.loadingFinished":
      case "Network.loadingFailed": {
        this.inflight.delete(p.requestId);
        this.lastActivity = Date.now();
        const t = this.trustTasks.get(p.requestId);
        if (t && method === "Network.loadingFinished") {
          this.trustTasks.delete(p.requestId);
          this.cdp
            .send("Network.getResponseBody", { requestId: p.requestId })
            .then((r) => {
              let body = r.body;
              try {
                body = JSON.parse(r.base64Encoded ? Buffer.from(r.body, "base64").toString() : r.body);
              } catch {}
              this.responses.push({ type: t.type, status: t.status, body, at: Date.now() });
              debug("trust task", t.status, t.type);
            })
            .catch(() => {});
        }
        break;
      }
      case "Runtime.exceptionThrown":
        this.consoleErrors.push(p.exceptionDetails?.exception?.description ?? p.exceptionDetails?.text);
        break;
      case "Runtime.consoleAPICalled":
        if (p.type === "error") {
          this.consoleErrors.push(p.args.map((a) => a.value ?? a.description ?? "").join(" "));
        }
        break;
    }
  }

  /** No request started or finished for `quiet` ms (long-lived streams ignored). */
  async networkIdle({ quiet = 500, timeout = TIMEOUT } = {}) {
    await until(
      () => {
        const now = Date.now();
        const active = [...this.inflight.values()].filter((t) => now - t < 5000).length;
        return active === 0 && now - this.lastActivity >= quiet;
      },
      { timeout, interval: 100, what: "the network to go idle" },
    );
  }

  async eval(expr) {
    const r = await this.cdp.send("Runtime.evaluate", {
      expression: `(() => { ${PAGE_HELPERS}; return (${expr}); })()`,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (r.exceptionDetails) {
      throw new Error(
        `page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`,
      );
    }
    return r.result.value;
  }

  url() {
    return this.eval("location.href").catch(() => "(unknown)");
  }

  async goto(url) {
    const loaded = new Promise((resolve) => {
      const off = this.cdp.on((m) => {
        if (m === "Page.loadEventFired") {
          off();
          resolve();
        }
      });
    });
    const r = await this.cdp.send("Page.navigate", { url });
    if (r.errorText) throw new Error(`could not open ${url}: ${r.errorText}`);
    await Promise.race([
      loaded,
      new Promise((_, rej) => setTimeout(() => rej(new Error(`timed out loading ${url}`)), TIMEOUT)),
    ]);
    await this.networkIdle();
  }

  state() {
    return this.eval("window.__vc.state()");
  }

  /** Wait until the page is in one of `states`; returns the state. */
  waitState(states, what) {
    return until(
      async () => {
        const s = await this.state();
        return states.includes(s) ? s : null;
      },
      { what: what ?? `the console to show one of: ${states.join(", ")}` },
    );
  }

  waitFor(spec, what) {
    return until(() => this.eval(`!!window.__vc.find(${JSON.stringify(spec)})`), {
      what: what ?? `element ${JSON.stringify(spec)}`,
    });
  }

  exists(spec) {
    return this.eval(`!!window.__vc.find(${JSON.stringify(spec)})`);
  }

  /** A real mouse click at the element's centre (so the page gets a user gesture). */
  async click(spec, what) {
    const desc = what ?? JSON.stringify(spec);
    const point = await until(
      () =>
        this.eval(`(() => {
          const el = window.__vc.find(${JSON.stringify(spec)});
          if (!el || el.disabled) return null;
          el.scrollIntoView({ block: "center", inline: "center" });
          const r = el.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`),
      { what: `an enabled ${desc}` },
    );
    debug("click", desc, point);
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
      await this.cdp.send("Input.dispatchMouseEvent", {
        type,
        x: point.x,
        y: point.y,
        button: "left",
        clickCount: type === "mouseMoved" ? 0 : 1,
      });
    }
  }

  /** Replace a text field's value by typing. */
  async type(selector, value) {
    const spec = { sel: selector };
    await this.waitFor(spec, `field ${selector}`);
    const focused = await this.eval(`(() => {
      const el = window.__vc.find(${JSON.stringify(spec)});
      el.scrollIntoView({ block: "center" });
      el.focus();
      el.select ? el.select() : document.execCommand("selectAll");
      let a = document.activeElement;
      while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
      return a === el;
    })()`);
    if (!focused) throw new Error(`could not focus ${selector} to type into it`);
    if (value === "") {
      await this.cdp.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "Backspace",
        code: "Backspace",
        windowsVirtualKeyCode: 8,
      });
      await this.cdp.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "Backspace",
        code: "Backspace",
        windowsVirtualKeyCode: 8,
      });
    } else {
      await this.cdp.send("Input.insertText", { text: value });
    }
    await until(
      () => this.eval(`window.__vc.find(${JSON.stringify(spec)}).value === ${JSON.stringify(value)}`),
      { timeout: 5000, what: `${selector} to read ${JSON.stringify(value)}` },
    );
  }

  /** Open a <details> disclosure by clicking its summary. */
  async openDetails(selector) {
    const open = await this.eval(`window.__vc.find({ sel: ${JSON.stringify(selector)}, any: true })?.open`);
    if (open === undefined) throw new Error(`no ${selector} on the page`);
    if (!open) await this.click({ sel: `${selector} > summary` }, `${selector} summary`);
    await until(() => this.eval(`window.__vc.find({ sel: ${JSON.stringify(selector)}, any: true }).open === true`), {
      timeout: 5000,
      what: `${selector} to open`,
    });
  }

  /** Set a <select>'s value the way React sees it. */
  async select(selector, value) {
    await this.waitFor({ sel: selector }, `select ${selector}`);
    const ok = await this.eval(`(() => {
      const el = window.__vc.find({ sel: ${JSON.stringify(selector)} });
      if (![...el.options].some((o) => o.value === ${JSON.stringify(value)})) return false;
      const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
      set.call(el, ${JSON.stringify(value)});
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    })()`);
    if (!ok) throw new Error(`${selector} has no option ${JSON.stringify(value)}`);
    await until(
      () => this.eval(`window.__vc.find({ sel: ${JSON.stringify(selector)} }).value === ${JSON.stringify(value)}`),
      { timeout: 5000, what: `${selector} to read ${JSON.stringify(value)}` },
    );
  }

  /** Make a checkbox / switch / radio `checked`, clicking its label if it is not. */
  async check(selector, checked = true) {
    const spec = { sel: selector, any: true };
    await this.waitFor(spec, `control ${selector}`);
    const now = await this.eval(`window.__vc.find(${JSON.stringify(spec)}).checked`);
    if (now === checked) return;
    // Click the control's label: switches draw a track over a hidden input.
    const marker = `vc-${Math.random().toString(36).slice(2)}`;
    await this.eval(`(() => {
      const el = window.__vc.find(${JSON.stringify(spec)});
      (el.closest("label") || el).setAttribute("data-vc", ${JSON.stringify(marker)});
    })()`);
    await this.click({ sel: `[data-vc="${marker}"]` }, `the label of ${selector}`);
    await until(() => this.eval(`window.__vc.find(${JSON.stringify(spec)}).checked === ${checked}`), {
      timeout: 5000,
      what: `${selector} to be ${checked ? "on" : "off"}`,
    });
  }

  async screenshot(name) {
    fs.mkdirSync(CHROME_DIR, { recursive: true });
    const file = path.join(CHROME_DIR, `${name}-${new Date().toISOString().replace(/[:.]/g, "-")}.png`);
    const r = await this.cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
    fs.writeFileSync(file, Buffer.from(r.data, "base64"));
    return file;
  }

  /** The last response to a Trust Task of `type` seen since `since`. */
  responseOf(type, since = 0) {
    return [...this.responses].reverse().find((r) => r.type === type && r.at >= since) ?? null;
  }

  waitResponse(type, since) {
    return until(() => this.responseOf(type, since), { what: `the console's ${type} answer` });
  }

  // ── WebAuthn virtual authenticator ──

  async setupAuthenticator() {
    await this.cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await this.cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    this.authenticatorId = authenticatorId;
    const saved = readPasskey();
    if (saved) {
      // The VTC rejects an assertion whose signature counter does not move
      // forward (webauthn-rs: "possibly compromised"). The counter is saved
      // after every run; the margin covers a run that died before saving.
      for (const cred of saved.credentials) {
        const credential = {
          ...cred,
          rpId: cred.rpId ?? new URL(BASE).hostname,
          signCount: (cred.signCount ?? 0) + SIGN_COUNT_MARGIN,
        };
        await this.cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
      }
      this.credentialsLoaded = true;
      // Save the raised counter now, so a run that dies before its final
      // export still leaves the next one ahead of the VTC's counter.
      await this.exportCredentials();
      debug(`re-added ${saved.credentials.length} passkey credential(s)`);
    }
  }

  async exportCredentials(extra = {}) {
    const { credentials } = await this.cdp.send("WebAuthn.getCredentials", {
      authenticatorId: this.authenticatorId,
    });
    if (!credentials.length) throw new Error("the virtual authenticator holds no credential to export");
    const prev = readPasskey();
    // CDP omits rpId (and userHandle) for a non-resident credential it was
    // handed with addCredential; carry them over so the file stays re-addable.
    for (const c of credentials) {
      const before = prev?.credentials?.find((p) => p.credentialId === c.credentialId);
      c.rpId ??= before?.rpId ?? new URL(BASE).hostname;
      if (before?.userHandle && !c.userHandle) c.userHandle = before.userHandle;
    }
    const out = {
      note: "CDP WebAuthn virtual-authenticator credential for the VTC admin console (infra/bin/console). Holds a private key: keep it in .state/.",
      origin: BASE,
      ...(prev ?? {}),
      ...extra,
      exportedAt: new Date().toISOString(),
      credentials,
    };
    fs.writeFileSync(PASSKEY_FILE, JSON.stringify(out, null, 2) + "\n", { mode: 0o600 });
    return out;
  }
}

function readPasskey() {
  try {
    return JSON.parse(fs.readFileSync(PASSKEY_FILE, "utf8"));
  } catch {
    return null;
  }
}

// ── Console flows ──────────────────────────────────────────────────────────

/**
 * Answer every dialog the console raises (the act's own confirmation, then
 * "Confirm with your passkey") until `done()` returns a value, failing on any
 * error the page shows.
 */
async function driveUntil(page, done, { what, errorScope = null, ignoreErrors = [] } = {}) {
  const seen = new Set();
  const before = new Set(await page.eval("window.__vc.errors()"));
  return until(
    async () => {
      const result = await done();
      if (result) return result;
      const dialogs = await page.eval("window.__vc.dialogs()");
      for (const d of dialogs) {
        const confirmLabel = d.buttons[d.buttons.length - 1];
        const key = `${d.title}|${confirmLabel}`;
        if (!seen.has(key)) {
          log(`dialog: "${d.title}" -> ${confirmLabel}`);
          seen.add(key);
        }
        await page.click({ sel: '[role="dialog"] button', text: confirmLabel, exact: true }, `"${confirmLabel}"`);
        await page.networkIdle({ quiet: 300 }).catch(() => {});
        return null;
      }
      const errs = (await page.eval(`window.__vc.errors()`)).filter(
        (e) => !before.has(e) && !ignoreErrors.some((re) => re.test(e)),
      );
      const scoped = errorScope ? errs.filter((e) => errorScope.test(e)) : errs;
      if (scoped.length) throw new Error(`the console reported: ${scoped.join(" | ")}`);
      return null;
    },
    { what },
  );
}

/** Open the console and get to a signed-in shell with a signing key. */
// `where` is the console page to land on. Not the dashboard by default: it
// fires a burst of signed reads, and the VTC counts documents from a console
// key against the same per-address budget as unauthenticated calls, so a few
// dashboard loads in a row get the address rate-limited.
async function ensureSignedIn(page, where = "/admin/vetting/requirements") {
  await page.goto(`${BASE}${where}`);
  for (let round = 0; round < 6; round++) {
    const s = await page.waitState(
      ["login", "setup-signing", "signing-check-failed", "cannot-sign", "shell"],
      "the console to finish loading",
    );
    debug("console state", s);
    if (s === "shell") {
      await page.networkIdle();
      return;
    }
    if (s === "cannot-sign") throw new Error("the console says this Chrome cannot sign (no WebCrypto Ed25519)");
    if (s === "signing-check-failed") {
      await page.click({ sel: "button", text: "Try again", exact: true });
      await page.networkIdle();
      continue;
    }
    if (s === "login") {
      if (!readPasskey()) {
        throw new Error(
          `no passkey in ${PASSKEY_FILE}: run \`infra/bin/console claim\` first`,
        );
      }
      // The VTC rate-limits unauthenticated calls per address; a refused
      // sign-in is retried after the wait the VTC names (bounded).
      for (let attempt = 1; ; attempt++) {
        log(`signing in with the passkey${attempt > 1 ? ` (attempt ${attempt})` : ""}`);
        const since = Date.now();
        await page.click({ sel: "button", text: "Sign in with a passkey" });
        const outcome = await until(
          async () => {
            const st = await page.state();
            if (st !== "login") return { ok: st };
            const alert = await page.eval(`window.__vc.text('.alert[role="alert"]')`);
            if (alert.length && !(await page.exists({ sel: "button", text: "Waiting for your passkey" }))) {
              return { error: alert.join(" ") };
            }
            return null;
          },
          { what: "the passkey sign-in to finish" },
        );
        if (outcome.ok) break;
        if (/session not found/i.test(outcome.error) && attempt < 5) {
          // A stale session cookie from an earlier run gets in the way: drop
          // the cookies and sign in afresh.
          log("stale console session; clearing cookies and signing in again");
          await page.cdp.send("Network.clearBrowserCookies");
          await page.goto(`${BASE}${where}`);
          await page.waitState(["login"], "the sign-in page");
          continue;
        }
        const limited = page.rateLimitedSince(since);
        if (!limited || attempt >= 8) throw new Error(`sign-in failed: ${outcome.error}`);
        const wait = Math.min(Math.max(limited.retryAfter ?? 5, 20) + 10 * attempt, 120);
        log(`the VTC rate-limited the sign-in; retrying in ${wait}s`);
        // Leave the sign-in page meanwhile: it keeps polling the VTC, which
        // spends the same per-address budget.
        await page.goto("about:blank");
        await new Promise((r) => setTimeout(r, wait * 1000));
        await page.goto(`${BASE}${where}`);
        await page.waitState(["login", "shell"], "the sign-in page");
        if ((await page.state()) === "shell") break;
      }
      continue;
    }
    if (s === "setup-signing") {
      log("setting up this browser's console signing key (one passkey confirmation)");
      const cap = await page.exists({ sel: "button", text: "Replace it and set up signing" });
      await page.click(
        cap
          ? { sel: "button", text: "Replace it and set up signing" }
          : { sel: "button", text: "Set up signing with your passkey" },
      );
      await driveUntil(
        page,
        async () => {
          const st = await page.state();
          if (st === "shell") return st;
          // Reached the key cap: replace the least recently used key.
          if (st === "setup-signing" && (await page.exists({ sel: "button", text: "Replace it and set up signing" }))) {
            return "cap";
          }
          return null;
        },
        { what: "signing to be set up" },
      );
    }
  }
  throw new Error("could not reach the signed-in console");
}

async function openRequirements(page) {
  const since = Date.now();
  await page.goto(`${BASE}/admin/vetting/requirements`);
  if ((await page.state()) !== "shell") {
    await ensureSignedIn(page);
    return openRequirements(page);
  }
  await page.waitFor({ sel: "h3", text: "Admission criteria" }, "the Requirements page");
  const [criteria, manifest] = await Promise.all([
    page.waitResponse(T_ACCEPTS_LIST, since),
    page.waitResponse(T_MANIFEST, since),
  ]);
  await page.networkIdle();
  for (const r of [criteria, manifest]) {
    if (r.status !== 200) {
      throw new Error(`the console's ${r.type} read failed (${r.status}): ${JSON.stringify(r.body?.payload ?? r.body)}`);
    }
  }
  return { criteria: allItemsFrom(page, since), manifest: manifest.body.payload };
}

/** Every accepts/list page the console read since `since` (it pages by cursor). */
function allItemsFrom(page, since) {
  const pages = page.responses.filter((r) => r.type === T_ACCEPTS_LIST && r.at >= since && r.status === 200);
  const byId = new Map();
  for (const p of pages) for (const c of p.body.payload.items ?? []) byId.set(c.id, c);
  return [...byId.values()];
}

/** Criteria in decision order, with what the manifest publishes for each. */
function describeCriteria(criteria, manifest) {
  const published = manifest?.criteria ?? [];
  const order = published.map((c) => c.id);
  const rank = (id) => (order.includes(id) ? order.indexOf(id) : order.length);
  return [...criteria]
    .sort((a, b) => rank(a.id) - rank(b.id))
    .map((c, i) => {
      const m = published.find((p) => p.id === c.id);
      const hidden = m?.vetting?.ext?.[HIDDEN_NS] ?? null;
      return {
        position: i + 1,
        ...c,
        requirementsDigest: m?.requirementsDigest ?? null,
        hiddenVetting: hidden ? summarizeHidden(hidden) : null,
      };
    });
}

function summarizeHidden(h) {
  return {
    suite: h.suite,
    vetterLabels: h.vetterLabels,
    tokenLabels: h.tokenLabels,
    dripPerTick: h.dripPerTick,
    tickLength: h.tickLength ?? "P3D (default)",
    events: h.events ?? [],
    helperKey: h.helperKey,
    tokenKey: h.tokenKey,
  };
}

// ── The form ───────────────────────────────────────────────────────────────

const METHODS = ["inPerson", "video", "priorAcquaintance"];
const METHOD_LABEL = { inPerson: "In person", video: "Video call", priorAcquaintance: "Prior acquaintance" };
const RELATIONSHIPS = ["none", "communityColleague", "sameEmployer", "family", "otherPersonal"];
const KNOWN_TOP = new Set(["id", "description", "admission", "invitationRequired", "query", "credentialIssuers", "vetting"]);
const KNOWN_VETTING = new Set([
  "version", "statementType", "minStatements", "minByMethod", "acceptedMethods", "eligibleVetters",
  "requiredClaims", "optionalClaims", "maxStatementAge", "acceptedDocumentClasses", "independence",
  "invitation", "decisionSla", "requirementsGrace", "governanceFrameworkUrl",
]);

function loadCriterionFile(file) {
  let c;
  try {
    c = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new UsageError(`cannot read criterion file ${file}: ${e.message}`);
  }
  if (!c || typeof c.id !== "string" || !c.id) throw new UsageError(`${file}: "id" is required`);
  if (!["automatic", "review"].includes(c.admission ?? "review")) {
    throw new UsageError(`${file}: "admission" must be "automatic" or "review"`);
  }
  for (const k of Object.keys(c)) if (!KNOWN_TOP.has(k)) throw new UsageError(`${file}: the console form has no field for "${k}"`);
  for (const k of Object.keys(c.vetting ?? {})) {
    if (!KNOWN_VETTING.has(k)) throw new UsageError(`${file}: the console form has no field for vetting.${k}`);
  }
  for (const m of c.vetting?.acceptedMethods ?? []) {
    if (!METHODS.includes(m)) throw new UsageError(`${file}: unknown vetting method "${m}"`);
  }
  return c;
}

/** Fill the "Add a criterion" form from the criterion's wire shape. Every field
 *  is set, so what is stored is what the file says (absent = empty / off). */
async function fillCriterionForm(realPage, c) {
  const v = c.vetting ?? null;
  // Record what each control should end up as, and read it all back at the end:
  // a re-render or a stray focus must not go unnoticed.
  const want = [];
  const page = {
    type: async (sel, val) => (want.push([sel, "value", val]), realPage.type(sel, val)),
    select: async (sel, val) => (want.push([sel, "value", val]), realPage.select(sel, val)),
    check: async (sel, on = true) => (want.push([sel, "checked", on]), realPage.check(sel, on)),
    eval: (x) => realPage.eval(x),
    openDetails: (sel) => realPage.openDetails(sel),
  };
  await fillFields(page, c, v);
  const got = await realPage.eval(`${JSON.stringify(want)}.map(([sel, prop]) => {
    const el = window.__vc.find({ sel, any: true });
    return el ? el[prop] : "(missing)";
  })`);
  const bad = want
    .map(([sel, , val], i) => (got[i] !== val ? `${sel}: want ${JSON.stringify(val)}, form has ${JSON.stringify(got[i])}` : null))
    .filter(Boolean);
  if (bad.length) throw new Error(`the form did not keep what was entered: ${bad.join("; ")}`);
}

async function fillFields(page, c, v) {
  await page.type("#criterion-id", c.id);
  await page.type("#criterion-description", c.description ?? "");
  await page.check(`input[name="criterion-admission"][value="${c.admission ?? "review"}"]`, true);
  await page.check("#criterion-invitation", Boolean(c.invitationRequired));
  await page.check("#criterion-credentials", c.query != null);
  if (c.query != null) {
    await page.select("#criterion-issuers", c.credentialIssuers ?? "community");
    await page.type("#criterion-query", JSON.stringify(c.query, null, 2));
  }
  await page.check("#criterion-vets", Boolean(v));
  if (!v) return;

  await page.select("#req-statement-type", v.statementType ?? "");
  await page.type("#req-min-statements", String(v.minStatements ?? ""));
  for (const m of METHODS) {
    await page.check(
      `.vet-method-checks label.checkbox:nth-child(${METHODS.indexOf(m) + 1}) input[type="checkbox"]`,
      (v.acceptedMethods ?? []).includes(m),
    );
  }
  for (const m of v.acceptedMethods ?? []) {
    await page.type(`#req-min-${m}`, v.minByMethod?.[m] != null ? String(v.minByMethod[m]) : "");
  }
  await page.type("#req-role", v.eligibleVetters?.role ?? "");
  await page.type("#req-required-claims", (v.requiredClaims ?? []).join(", "));
  await page.type("#req-optional-claims", (v.optionalClaims ?? []).join(", "));
  await page.type("#req-max-age", v.maxStatementAge ?? "");
  const floor = Array.isArray(v.acceptedDocumentClasses);
  await page.check("#req-document-floor", floor);
  if (floor) await page.type("#req-documents", v.acceptedDocumentClasses.join(", "));
  await page.check("#req-consistent", Boolean(v.independence?.requireConsistentIdentityCommitment));
  for (const rel of RELATIONSHIPS) {
    const cap = v.independence?.maxByDeclaredRelationship?.[rel];
    await page.type(`#req-cap-${rel}`, cap != null ? String(cap) : "");
  }
  await page.select("#req-invitation", v.invitation ?? "");
  await page.openDetails(`form[aria-labelledby="editor-title"] details.vet-details`);
  await page.type("#req-sla", v.decisionSla ?? "");
  await page.type("#req-grace", v.requirementsGrace ?? "");
  await page.type("#req-governance", v.governanceFrameworkUrl ?? "");
  await page.type("#req-version", v.version ?? "0.1");
  // Sanity-check the method checkboxes by their labels (the nth-child mapping above).
  const labels = await page.eval(
    `[...window.__vc.all(".vet-method-checks label.checkbox")].map((l) => [window.__vc.norm(l.textContent), l.querySelector("input").checked])`,
  );
  for (const [label, checked] of labels) {
    const m = METHODS.find((k) => METHOD_LABEL[k] === label);
    if (m && checked !== (v.acceptedMethods ?? []).includes(m)) {
      throw new Error(`method checkbox "${label}" did not take the value from the file`);
    }
  }
}

/** Fields worth comparing between the file and what the VTC stored. */
function sameCriterion(want, got) {
  const pick = (c) => JSON.stringify(canon({ ...c, description: c.description ?? undefined }));
  const strip = ({ id, description, admission, invitationRequired, query, credentialIssuers, vetting }) => ({
    id,
    description: description || undefined,
    admission: admission ?? "review",
    invitationRequired: invitationRequired || undefined,
    query: query ?? undefined,
    credentialIssuers: credentialIssuers ?? undefined,
    vetting: vetting ? canon({ ...vetting, ext: undefined }) : undefined,
  });
  return pick(strip(want)) === pick(strip(got));
}

function canon(x) {
  if (Array.isArray(x)) return x.map(canon);
  if (x && typeof x === "object") {
    const o = {};
    for (const k of Object.keys(x).sort()) if (x[k] !== undefined && x[k] !== null) o[k] = canon(x[k]);
    return o;
  }
  return x;
}

// ── Subcommands ────────────────────────────────────────────────────────────

function readInvite() {
  let text;
  try {
    text = fs.readFileSync(INVITE_FILE, "utf8");
  } catch {
    throw new Error(`no invitation at ${INVITE_FILE}; mint one with infra/bin/vtc-offline admin invite --ttl 86400 > ${INVITE_FILE}`);
  }
  const url = text.match(/https?:\/\/\S+\/admin\/install\?token=[A-Za-z0-9._-]+/)?.[0];
  const code = text.match(/Claim code[^\n]*\n\s*([A-Z0-9]{6,})/)?.[1];
  if (!url || !code) throw new Error(`${INVITE_FILE} does not hold an install URL and a claim code`);
  return { url, code };
}

async function cmdClaim(page) {
  if (readPasskey()) {
    log(`a passkey is already saved in ${PASSKEY_FILE}; checking it signs in`);
    await ensureSignedIn(page);
    const saved = readPasskey();
    console.log(JSON.stringify({ claimed: "already", adminDid: saved.adminDid ?? null, signedIn: true }, null, 2));
    return;
  }
  const { url, code } = readInvite();
  log(`claiming the invitation in ${path.relative(process.cwd(), INVITE_FILE)}`);
  await page.goto(url);
  const s = await page.waitState(["install-code", "install-error"], "the install page");
  if (s === "install-error") {
    throw new Error(`the install page refused the URL: ${(await page.eval("window.__vc.errors()")).join(" | ")}`);
  }
  await page.type('.install-page input[placeholder="e.g. ABCDEFGHJK"]', code);
  log("claim code entered; registering the passkey (create + one proving assertion)");
  await page.click({ sel: ".install-page button", text: "Continue", exact: true }, '"Continue"');
  const done = await page.waitState(["install-success", "install-error"], "the install claim to finish");
  if (done === "install-error") {
    const errs = await page.eval("window.__vc.errors()");
    throw new Error(
      `the claim was refused: ${errs.join(" | ")}. If the invitation is spent or expired, mint a new one: ` +
        `infra/bin/vtc-offline admin invite --ttl 86400 > ${INVITE_FILE}`,
    );
  }
  const adminDid = await page.eval(`window.__vc.text(".install-page dd code")[0] || null`);
  const saved = await page.exportCredentials({ adminDid, claimedAt: new Date().toISOString() });
  page.credentialsLoaded = true;
  log(`claimed; admin DID ${adminDid}; passkey exported to ${PASSKEY_FILE} (${saved.credentials.length} credential)`);

  // Start a fresh browser so the sign-in check proves the exported credential
  // is enough (exactly what every later run does).
  return { reopen: true, adminDid };
}

async function cmdCheckSignIn(page, adminDid) {
  await ensureSignedIn(page);
  const whoami = page.responseOf(T_WHOAMI);
  const subject = whoami?.body?.payload?.session?.subject ?? null;
  console.log(
    JSON.stringify(
      { claimed: true, adminDid, signedIn: true, consoleSubject: subject, passkeyFile: PASSKEY_FILE },
      null,
      2,
    ),
  );
}

async function cmdShow(page) {
  await ensureSignedIn(page);
  const { criteria, manifest } = await openRequirements(page);
  console.log(JSON.stringify({ vtc: manifest.communityDid, criteria: describeCriteria(criteria, manifest) }, null, 2));
}

async function cmdAddCriterion(page, file) {
  const want = loadCriterionFile(file);
  await ensureSignedIn(page);
  const { criteria } = await openRequirements(page);
  const existing = criteria.find((c) => c.id === want.id);
  if (existing) {
    const same = sameCriterion(want, existing);
    log(
      `criterion "${want.id}" already exists${same ? " with these requirements" : " but DIFFERS from the file (not changed; remove it first to replace it)"}`,
    );
    console.log(JSON.stringify({ added: false, exists: true, matchesFile: same, criterion: existing }, null, 2));
    return;
  }
  log(`adding criterion "${want.id}" through Vetting → Requirements`);
  await page.click({ sel: "button", text: "Add a criterion", exact: true });
  await page.waitFor({ sel: "#criterion-id" }, "the criterion editor");
  await fillCriterionForm(page, want);
  const formErrors = await page.eval(`window.__vc.text("form .finding.error, form .field-error, form [id$='-error']")`);
  if (formErrors.length) throw new Error(`the form refuses the criterion: ${formErrors.join(" | ")}`);
  const since = Date.now();
  await page.click({ sel: 'form button[type="submit"]', text: "Add criterion", exact: true }, '"Add criterion"');
  await driveUntil(
    page,
    async () => {
      // Saved: the editor closed and the console re-read the criteria with it in.
      if (await page.exists({ sel: "#criterion-id" })) return null;
      const r = page.responseOf(T_ACCEPTS_LIST, since);
      return r && (r.body?.payload?.items ?? []).some((c) => c.id === want.id) ? true : null;
    },
    { what: `criterion "${want.id}" to be saved` },
  );
  await page.networkIdle();
  const toasts = await page.eval(`window.__vc.text(".toast")`);
  if (toasts.length) log(`console: ${toasts.join(" | ")}`);
  const after = await openRequirements(page);
  const stored = describeCriteria(after.criteria, after.manifest).find((c) => c.id === want.id);
  if (!stored) {
    // Parked for other administrators' approval rather than applied.
    throw new Error(`"${want.id}" was not stored. Console said: ${toasts.join(" | ") || "(nothing)"}`);
  }
  console.log(JSON.stringify({ added: true, matchesFile: sameCriterion(want, stored), criterion: stored }, null, 2));
}

async function cmdRemoveCriterion(page, id) {
  await ensureSignedIn(page);
  const { criteria, manifest } = await openRequirements(page);
  const existing = criteria.find((c) => c.id === id);
  if (!existing) {
    log(`criterion "${id}" does not exist; nothing to remove`);
    console.log(JSON.stringify({ removed: false, exists: false }, null, 2));
    return;
  }
  // Keep what was removed, so it can be added back (e.g. `review`, to move it last).
  const backup = path.join(STATE, `console-removed-${id}.json`);
  const { createdAt, createdByDid, ...plain } = existing;
  void createdAt, void createdByDid;
  fs.writeFileSync(backup, JSON.stringify(plain, null, 2) + "\n");
  log(`removing criterion "${id}" (saved a copy to ${backup})`);
  const position = describeCriteria(criteria, manifest).findIndex((c) => c.id === id) + 1;
  // Match the card's heading exactly ("N. Criterion <id>"), never a prefix of another id.
  const heading = await page.eval(`window.__vc.text("section.card h3").find((t) => t === "${position}. Criterion ${id}") || null`);
  if (!heading) throw new Error(`could not find the card for "${id}" on the Requirements page`);
  await page.eval(`(() => {
    const h = window.__vc.all("section.card h3").find((x) => window.__vc.norm(x.textContent) === ${JSON.stringify(`${position}. Criterion ${id}`)});
    const b = [...h.closest("section.card").querySelectorAll(".form-actions button")].find((x) => window.__vc.norm(x.textContent) === "Remove");
    b.setAttribute("data-vc", "remove-target");
  })()`);
  const since = Date.now();
  await page.click({ sel: '[data-vc="remove-target"]' }, `"Remove" on ${id}`);
  await driveUntil(
    page,
    async () => {
      const r = page.responseOf(T_ACCEPTS_LIST, since);
      return r && !(r.body?.payload?.items ?? []).some((c) => c.id === id) ? true : null;
    },
    { what: `criterion "${id}" to be removed` },
  );
  await page.networkIdle();
  const after = await openRequirements(page);
  if (after.criteria.some((c) => c.id === id)) throw new Error(`"${id}" is still listed after removal`);
  console.log(JSON.stringify({ removed: true, savedTo: backup, criteria: describeCriteria(after.criteria, after.manifest).map((c) => c.id) }, null, 2));
}

async function cmdHiddenOn(page, id) {
  await ensureSignedIn(page);
  let { criteria, manifest } = await openRequirements(page);
  let rows = describeCriteria(criteria, manifest);
  const row = rows.find((c) => c.id === id);
  if (!row) throw new Error(`no criterion "${id}"; add it first`);
  if (!row.vetting) throw new Error(`criterion "${id}" asks for no vetting, so hidden vetting cannot qualify it`);
  if (!row.hiddenVetting) {
    const other = rows.find((c) => c.hiddenVetting);
    if (other) throw new Error(`hidden vetting is already on for "${other.id}"; a community runs it on one criterion`);
    const title = `${row.position}. Criterion ${id}`;
    const found = await page.eval(`(() => {
      const h = window.__vc.all("section.card h3").find((x) => window.__vc.norm(x.textContent) === ${JSON.stringify(title)});
      if (!h) return false;
      const b = [...h.closest("section.card").querySelectorAll("button")].find((x) => window.__vc.norm(x.textContent) === "Turn on hidden vetting");
      if (!b) return false;
      b.setAttribute("data-vc", "hidden-on-target");
      return true;
    })()`);
    if (!found) {
      throw new Error(
        `no "Turn on hidden vetting" button on "${id}"'s card: this VTC build may not support hidden vetting (vetting-pcs)`,
      );
    }
    log(`turning on hidden vetting for "${id}"`);
    const since = Date.now();
    await page.click({ sel: '[data-vc="hidden-on-target"]' }, `"Turn on hidden vetting" on ${id}`);
    await driveUntil(
      page,
      async () => {
        const r = page.responseOf(T_MANIFEST, since);
        const c = r?.body?.payload?.criteria?.find((x) => x.id === id);
        return c?.vetting?.ext?.[HIDDEN_NS] ? true : null;
      },
      { what: `hidden vetting to be published for "${id}"` },
    );
    await page.networkIdle();
    const toasts = await page.eval(`window.__vc.text(".toast")`);
    if (toasts.length) log(`console: ${toasts.join(" | ")}`);
    ({ criteria, manifest } = await openRequirements(page));
    rows = describeCriteria(criteria, manifest);
  } else {
    log(`hidden vetting is already on for "${id}"`);
  }
  const now = rows.find((c) => c.id === id);
  // What the console's card shows, and the stored configuration it read.
  const card = await page.eval(`(() => {
    const h = window.__vc.all("section.card h3").find((x) => window.__vc.norm(x.textContent) === ${JSON.stringify(`${now.position}. Criterion ${id}`)});
    const box = h && h.closest("section.card").querySelector('[aria-label="Hidden vetting"]');
    if (!box) return null;
    const dts = [...box.querySelectorAll(":scope > dl > dt")];
    return Object.fromEntries(dts.map((dt) => [window.__vc.norm(dt.textContent), window.__vc.norm(dt.nextElementSibling?.textContent)]));
  })()`);
  const show = page.responseOf(T_HIDDEN_SHOW);
  console.log(
    JSON.stringify(
      {
        criterion: id,
        hiddenVetting: "on",
        requirementsDigest: now.requirementsDigest,
        published: now.hiddenVetting,
        consoleCard: card,
        stored: show?.status === 200 ? show.body.payload : null,
      },
      null,
      2,
    ),
  );
}

// ── Join requests ──────────────────────────────────────────────────────────

function joinRow(r) {
  return { id: r.id, personaDid: r.applicantDid, state: r.status, submittedAt: r.submittedAt ?? null };
}

/** The console's Join requests page lists pending requests; read what it fetched. */
async function readPendingJoins(page) {
  const since = Date.now();
  await page.goto(`${BASE}/admin/join-requests`);
  if ((await page.state()) !== "shell") {
    await ensureSignedIn(page, "/admin/join-requests");
    return readPendingJoins(page);
  }
  const r = await until(
    () => {
      const hit = [...page.responses].reverse().find(
        (x) => x.type === T_JR_LIST && x.at >= since && x.body?.payload && "items" in x.body.payload,
      );
      return hit ?? null;
    },
    { what: "the console's join-request listing" },
  );
  await page.networkIdle();
  if (r.status !== 200) throw new Error(`the join-request listing failed (${r.status}): ${JSON.stringify(r.body?.payload)}`);
  return r.body.payload.items.map(joinRow);
}

async function cmdJoinRequests(page) {
  await ensureSignedIn(page, "/admin/join-requests");
  const rows = await readPendingJoins(page);
  console.log(JSON.stringify({ pending: rows }, null, 2));
}

async function showJoin(page, id) {
  const since = Date.now();
  await page.goto(`${BASE}/admin/join-requests/${encodeURIComponent(id)}`);
  const r = await page.waitResponse(T_JR_SHOW, since);
  await page.networkIdle();
  if (r.status !== 200) {
    throw new Error(`the console could not load join request ${id} (${r.status}): ${JSON.stringify(r.body?.payload)}`);
  }
  return r.body.payload.request;
}

async function cmdApproveJoin(page, target) {
  await ensureSignedIn(page, "/admin/join-requests");
  let id = target;
  if (target.startsWith("did:")) {
    const pending = await readPendingJoins(page);
    const hit = pending.filter((r) => r.personaDid === target);
    if (!hit.length) {
      throw new Error(`no pending join request from ${target} (pending: ${pending.map((r) => r.personaDid).join(", ") || "none"})`);
    }
    id = hit[hit.length - 1].id;
    log(`pending request for ${target}: ${id}`);
  }
  const req = await showJoin(page, id);
  if (req.status !== "pending") {
    log(`join request ${id} is already ${req.status}; nothing to decide`);
    console.log(JSON.stringify({ approved: false, alreadyDecided: true, request: joinRow(req) }, null, 2));
    return;
  }
  log(`approving join request ${id} from ${req.applicantDid}`);
  const since = Date.now();
  await page.click({ sel: "section.card button", text: "Approve", exact: true }, '"Approve"');
  const decided = await driveUntil(
    page,
    async () => {
      const d = page.responseOf(T_JR_DECIDE, since);
      if (d && d.status === 200) return d;
      if (d && d.status !== 403) {
        throw new Error(`the VTC refused the approval (${d.status}): ${JSON.stringify(d.body?.payload)}`);
      }
      return null;
    },
    { what: `join request ${id} to be approved` },
  );
  await page.networkIdle();
  const after = await showJoin(page, id);
  console.log(JSON.stringify({ approved: after.status === "approved", decision: decided.body.payload, request: joinRow(after) }, null, 2));
}

// ── Main ───────────────────────────────────────────────────────────────────

const HELP = `usage: infra/bin/console <command> [args]

  claim                     claim .state/vtc-admin-invite.txt with a virtual passkey,
                            export it to .state/console-passkey.json, then sign in
  add-criterion <file.json> add a join criterion via Vetting → Requirements
                            (exits 0 and reports if the id already exists)
  remove-criterion <id>     remove a criterion (a copy goes to .state/console-removed-<id>.json)
  hidden-on <criterion-id>  turn on Hidden vetting (PCS) and print what is published
  show                      print the criteria, in decision order, as JSON
  join-requests             list pending join requests as JSON (id, persona DID, state)
  approve-join <id|did>     approve a pending join request (Join requests → Approve),
                            answering the passkey step-up if one is asked

env: VTC_URL (default http://localhost:8200), CHROME_BIN, CONSOLE_TIMEOUT_MS,
     CONSOLE_VERBOSE=1`;

async function withBrowser(fn) {
  const { cdp, close } = await launchChrome();
  const page = new Page(cdp);
  try {
    await page.init();
    await page.setupAuthenticator();
    await page.restoreCookies();
    return await fn(page);
  } catch (err) {
    let shot = "(no screenshot)";
    try {
      shot = await page.screenshot("failure");
    } catch {}
    const url = await Promise.race([page.url(), new Promise((r) => setTimeout(() => r("(unknown)"), 2000))]);
    err.message = `${err.message}\n  page: ${url}\n  screenshot: ${shot}` +
      (page.consoleErrors.length ? `\n  browser console errors: ${page.consoleErrors.slice(-3).join(" | ")}` : "");
    throw err;
  } finally {
    // Keep the passkey's signature counter current (see setupAuthenticator).
    if (readPasskey() && page.authenticatorId && page.credentialsLoaded) {
      await page.exportCredentials().catch((e) => log(`could not save the passkey counter: ${e.message}`));
    }
    await page.saveCookies().catch(() => {});
    await close();
  }
}

async function main() {
  const [cmd, arg] = process.argv.slice(2);
  switch (cmd) {
    case "claim": {
      const r = await withBrowser(cmdClaim);
      if (r?.reopen) await withBrowser((page) => cmdCheckSignIn(page, r.adminDid));
      return;
    }
    case "add-criterion":
      if (!arg) throw new UsageError("add-criterion needs a JSON file");
      return withBrowser((page) => cmdAddCriterion(page, path.resolve(arg)));
    case "remove-criterion":
      if (!arg) throw new UsageError("remove-criterion needs a criterion id");
      return withBrowser((page) => cmdRemoveCriterion(page, arg));
    case "hidden-on":
      if (!arg) throw new UsageError("hidden-on needs a criterion id");
      return withBrowser((page) => cmdHiddenOn(page, arg));
    case "show":
      return withBrowser(cmdShow);
    case "join-requests":
      return withBrowser(cmdJoinRequests);
    case "approve-join":
      if (!arg) throw new UsageError("approve-join needs a join request id or persona DID");
      return withBrowser((page) => cmdApproveJoin(page, arg));
    case undefined:
    case "help":
    case "-h":
    case "--help":
      console.log(HELP);
      return;
    default:
      throw new UsageError(`unknown command "${cmd}"`);
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    if (err instanceof UsageError) {
      console.error(`console: ${err.message}\n\n${HELP}`);
      process.exit(2);
    }
    console.error(`console: error: ${err.message}`);
    process.exit(1);
  },
);
