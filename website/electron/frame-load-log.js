"use strict";

/**
 * Frame-load diagnostics for the dashboard's own webContents.
 *
 * The remote-crew panes are cross-origin iframes pointed at SSH-forwarded
 * loopback ports. When one of them never becomes a live document the UI shows
 * "loading pane" forever and NOTHING is recorded anywhere: the main window
 * hooked no load events, the remote gateway keeps no HTTP access log (no
 * aiohttp `access_log` is configured), and a packaged app has no devtools
 * console to open. So the one question that decides the diagnosis — did the
 * frame ever navigate, and with what status — had no answer in any log.
 *
 * This module closes that gap by journaling frame navigations, frame load
 * failures, and renderer console errors into the same gateway-launch.log the
 * rest of the launch path writes to.
 *
 * Kept electron-free so node:test can drive the formatters directly.
 */

/**
 * Identical console errors repeat every paint (a broken pane can emit the same
 * line hundreds of times), and this log is read by tailing it. Cap the repeats
 * so one loud message cannot bury the navigation lines around it.
 */
const CONSOLE_REPEAT_LIMIT = 3;

/**
 * The dashboard's own pane journal (`website/src/lib/paneLog.ts`) emits at INFO
 * level and is allowlisted below regardless of severity: those lines are the
 * renderer half of this diagnosis and are deliberately few.
 */
const PANE_LOG_PREFIX = "[pane]";

/**
 * A higher cap for allowlisted lines. A pane stuck in a re-mint loop repeats the
 * same journal line, and the REPEAT COUNT is the finding there — capping it at
 * three would hide the loop this instrumentation exists to catch.
 */
const PANE_REPEAT_LIMIT = 20;

/**
 * A URL safe to journal.
 *
 * A pane URL carries the crew's session token in `?token=…`, which must never
 * be written to a log file. The query is dropped, but the line still records
 * THAT a token was present: the failure worth diagnosing is a token the remote
 * rejected, so its presence is signal while its value is only a secret.
 */
function safeUrl(url) {
  const text = String(url || "");
  const cut = text.indexOf("?");
  if (cut < 0) return text;
  const query = text.slice(cut + 1);
  const marker = /(^|&)token=/.test(query) ? "?token=<redacted>" : "?<query>";
  return text.slice(0, cut) + marker;
}

/** Which frame the event is about — the dashboard itself, or a crew pane. */
function frameLabel(isMainFrame) {
  return isMainFrame ? "main" : "subframe";
}

/**
 * A navigation that STARTED. Paired with the committed-navigation line below,
 * this is what separates the two failures that look identical on screen: a start
 * with no commit is a request that went out and never came back (a dead tunnel
 * that still accepts locally), while no start at all means the frame was never
 * pointed anywhere and no amount of remote debugging would have found it.
 *
 * Same-document navigations are skipped — the dashboard is a router-driven SPA
 * and they carry no load information.
 */
function formatFrameStartNavigation({ url, isInPlace, isMainFrame } = {}) {
  if (isInPlace) return "";
  return `frame navigation STARTED (${frameLabel(isMainFrame)}) ${safeUrl(url)}`;
}

/**
 * A committed navigation. `status` is the HTTP code the frame actually got, so
 * a pane the remote answered with 403 (token refused) is distinguishable from
 * one that was never requested at all — the latter logs no line here.
 */
function formatFrameNavigate({ url, httpResponseCode, isMainFrame } = {}) {
  const status = Number.isFinite(httpResponseCode) ? httpResponseCode : "?";
  return `frame navigated (${frameLabel(isMainFrame)}) status=${status} ${safeUrl(url)}`;
}

/**
 * A navigation that started and failed. The net error code is the whole point:
 * ERR_CONNECTION_REFUSED means the forwarded port had no listener, while
 * ERR_BLOCKED_BY_RESPONSE means the response arrived and framing was refused.
 */
function formatFrameFailLoad({ errorCode, errorDescription, url, isMainFrame } = {}) {
  const code = Number.isFinite(errorCode) ? errorCode : "?";
  const desc = String(errorDescription || "").trim() || "unknown";
  return `frame load FAILED (${frameLabel(isMainFrame)}) code=${code} ${desc} ${safeUrl(url)}`;
}

/**
 * Normalize both `console-message` shapes.
 *
 * Electron >= 35 emits a single details object (`level` is a string); the
 * legacy positional form (`event, level:number, message, line, sourceId`) is
 * deprecated but still delivered, and is what the rest of this app reads.
 * Accepting both means this keeps working across the upgrade that drops one.
 *
 * @returns {{severity: string, message: string, sourceId: string, line: number}|null}
 */
function normalizeConsoleMessage(args) {
  const list = Array.isArray(args) ? args : [];
  const first = list[0];
  // New shape: the sole argument carries the message itself.
  if (first && typeof first === "object" && typeof first.message === "string") {
    return {
      severity: severityFromLevel(first.level),
      message: first.message,
      sourceId: String(first.sourceId || ""),
      line: Number(first.lineNumber) || 0,
    };
  }
  // Legacy shape: args[0] is the event, and the payload follows it.
  if (typeof list[2] === "string") {
    return {
      severity: severityFromLevel(list[1]),
      message: list[2],
      sourceId: String(list[4] || ""),
      line: Number(list[3]) || 0,
    };
  }
  return null;
}

/** Map either level encoding onto one vocabulary. */
function severityFromLevel(level) {
  if (typeof level === "string") {
    const name = level.toLowerCase();
    if (name === "error" || name === "warning" || name === "info" || name === "debug") return name;
    return "info";
  }
  if (level >= 3) return "error";
  if (level === 2) return "warning";
  if (level === 1) return "info";
  return "debug";
}

/**
 * `suppressedNext` marks the line as the last of its kind, so a reader who sees
 * three identical entries knows the silence after them is the cap, not recovery.
 */
function formatConsoleMessage({ severity, message, sourceId, line }, suppressedNext = false) {
  const where = sourceId ? ` (${safeUrl(sourceId)}:${line})` : "";
  const tail = suppressedNext ? " [further repeats suppressed]" : "";
  return `renderer console [${severity}]: ${message}${where}${tail}`;
}

/**
 * Attach the diagnostics to `contents`, writing through `log`.
 *
 * Console output is filtered to ERRORS plus the dashboard's own `[pane]` journal.
 * Warnings on this surface are dominated by per-paint noise the renderer emits by
 * the hundred (`content-visibility`, `ResizeObserver loop completed`), which
 * would push the load events that matter out of any readable tail.
 *
 * Tolerates a missing or partial webContents so a caller never has to guard:
 * this is diagnostics and must not be able to break window creation.
 */
function attachFrameLoadLogging(contents, log) {
  if (!contents || typeof contents.on !== "function") return false;
  if (typeof log !== "function") return false;

  const repeats = new Map();

  contents.on("did-start-navigation", (_event, url, isInPlace, isMainFrame) => {
    const line = formatFrameStartNavigation({ url, isInPlace, isMainFrame });
    if (line) log(line);
  });

  contents.on("did-frame-navigate", (_event, url, httpResponseCode, _statusText, isMainFrame) => {
    log(formatFrameNavigate({ url, httpResponseCode, isMainFrame }));
  });

  contents.on("did-fail-load", (_event, errorCode, errorDescription, url, isMainFrame) => {
    log(formatFrameFailLoad({ errorCode, errorDescription, url, isMainFrame }));
  });

  contents.on("console-message", (...args) => {
    const entry = normalizeConsoleMessage(args);
    if (!entry) return;
    const allowlisted = entry.message.startsWith(PANE_LOG_PREFIX);
    if (!allowlisted && entry.severity !== "error") return;
    const limit = allowlisted ? PANE_REPEAT_LIMIT : CONSOLE_REPEAT_LIMIT;
    const count = (repeats.get(entry.message) || 0) + 1;
    repeats.set(entry.message, count);
    if (count > limit) return;
    log(formatConsoleMessage(entry, count === limit));
  });

  return true;
}

module.exports = {
  CONSOLE_REPEAT_LIMIT,
  PANE_LOG_PREFIX,
  PANE_REPEAT_LIMIT,
  attachFrameLoadLogging,
  formatConsoleMessage,
  formatFrameFailLoad,
  formatFrameNavigate,
  formatFrameStartNavigation,
  normalizeConsoleMessage,
  safeUrl,
};
