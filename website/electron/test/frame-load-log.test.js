"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CONSOLE_REPEAT_LIMIT,
  PANE_LOG_PREFIX,
  PANE_REPEAT_LIMIT,
  attachFrameLoadLogging,
  formatFrameFailLoad,
  formatFrameNavigate,
  formatFrameStartNavigation,
  normalizeConsoleMessage,
  safeUrl,
} = require("../frame-load-log");

/** A webContents stand-in that records handlers and can replay events. */
function fakeContents() {
  const handlers = new Map();
  return {
    handlers,
    on(event, handler) {
      handlers.set(event, handler);
      return this;
    },
    emit(event, ...args) {
      const handler = handlers.get(event);
      if (!handler) throw new Error(`no handler for ${event}`);
      handler(...args);
    },
  };
}

function attachedLog() {
  const lines = [];
  const contents = fakeContents();
  const attached = attachFrameLoadLogging(contents, (line) => lines.push(line));
  return { lines, contents, attached };
}

describe("frame-load-log URL redaction", () => {
  it("never writes a session token to the log", () => {
    const url = "http://localhost:7778/?token=supersecretvalue";
    assert.equal(safeUrl(url), "http://localhost:7778/?token=<redacted>");
    for (const line of [
      formatFrameNavigate({ url, httpResponseCode: 200, isMainFrame: false }),
      formatFrameFailLoad({ errorCode: -102, errorDescription: "ERR_CONNECTION_REFUSED", url }),
    ]) {
      assert.doesNotMatch(line, /supersecretvalue/, "the token must not reach the log");
      assert.match(line, /token=<redacted>/, "but its presence must still be recorded");
    }
  });

  it("keeps the port and path, which are the diagnostic content", () => {
    const line = formatFrameNavigate({
      url: "http://localhost:7778/chat/abc?token=x",
      httpResponseCode: 200,
      isMainFrame: false,
    });
    assert.match(line, /http:\/\/localhost:7778\/chat\/abc/);
  });

  it("marks a non-token query without dropping the fact there was one", () => {
    assert.equal(safeUrl("http://localhost:5476/?foo=1"), "http://localhost:5476/?<query>");
  });

  it("passes through a URL with no query untouched", () => {
    assert.equal(safeUrl("http://localhost:5476/"), "http://localhost:5476/");
  });
});

describe("frame-load-log formatting", () => {
  it("distinguishes a crew pane from the dashboard itself", () => {
    assert.match(
      formatFrameNavigate({ url: "http://localhost:7778/", httpResponseCode: 200, isMainFrame: false }),
      /subframe/,
    );
    assert.match(
      formatFrameNavigate({ url: "http://localhost:5476/", httpResponseCode: 200, isMainFrame: true }),
      /main/,
    );
  });

  it("records the HTTP status, so a refused token is visible as 403", () => {
    assert.match(
      formatFrameNavigate({ url: "http://localhost:7778/", httpResponseCode: 403, isMainFrame: false }),
      /status=403/,
    );
  });

  it("records the net error code and description on a failed load", () => {
    const line = formatFrameFailLoad({
      errorCode: -102,
      errorDescription: "ERR_CONNECTION_REFUSED",
      url: "http://localhost:7778/",
      isMainFrame: false,
    });
    assert.match(line, /FAILED/);
    assert.match(line, /code=-102/);
    assert.match(line, /ERR_CONNECTION_REFUSED/);
  });

  it("names a missing description rather than logging an empty gap", () => {
    assert.match(formatFrameFailLoad({ errorCode: -2, url: "http://x/" }), /unknown/);
  });

  it("does not print a bare '?' status as a number", () => {
    assert.match(formatFrameNavigate({ url: "http://x/" }), /status=\?/);
  });

  it("announces a navigation that merely started, before any commit", () => {
    const line = formatFrameStartNavigation({
      url: "http://localhost:7778/?token=s",
      isMainFrame: false,
    });
    assert.match(line, /frame navigation STARTED \(subframe\)/);
    assert.match(line, /token=<redacted>/);
    assert.doesNotMatch(line, /\bstatus=/, "nothing has committed yet, so there is no status");
  });

  it("stays silent for a same-document navigation, which carries no load info", () => {
    assert.equal(
      formatFrameStartNavigation({ url: "http://localhost:5476/chat", isInPlace: true }),
      "",
      "the dashboard is a router-driven SPA and would otherwise flood the log",
    );
  });
});

describe("frame-load-log console normalization", () => {
  it("reads the Electron >= 35 details-object shape", () => {
    const entry = normalizeConsoleMessage([
      { level: "error", message: "boom", lineNumber: 42, sourceId: "app.js" },
    ]);
    assert.deepEqual(entry, { severity: "error", message: "boom", sourceId: "app.js", line: 42 });
  });

  it("reads the legacy positional shape the rest of the app still uses", () => {
    const entry = normalizeConsoleMessage([{}, 3, "boom", 42, "app.js"]);
    assert.deepEqual(entry, { severity: "error", message: "boom", sourceId: "app.js", line: 42 });
  });

  it("maps every numeric level onto the shared vocabulary", () => {
    const levels = [0, 1, 2, 3].map((n) => normalizeConsoleMessage([{}, n, "m"]).severity);
    assert.deepEqual(levels, ["debug", "info", "warning", "error"]);
  });

  it("returns null for an unrecognized emission instead of inventing a message", () => {
    assert.equal(normalizeConsoleMessage([]), null);
    assert.equal(normalizeConsoleMessage([{}, 3]), null);
    assert.equal(normalizeConsoleMessage(undefined), null);
  });
});

describe("frame-load-log attachment", () => {
  it("logs a committed subframe navigation", () => {
    const { lines, contents } = attachedLog();
    contents.emit("did-frame-navigate", {}, "http://localhost:7778/?token=s", 200, "OK", false);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /frame navigated \(subframe\) status=200 http:\/\/localhost:7778\/\?token=<redacted>/);
  });

  it("logs a failed load with its net error", () => {
    const { lines, contents } = attachedLog();
    contents.emit("did-fail-load", {}, -102, "ERR_CONNECTION_REFUSED", "http://localhost:7778/", false);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /frame load FAILED \(subframe\) code=-102 ERR_CONNECTION_REFUSED/);
  });

  it("forwards console errors", () => {
    const { lines, contents } = attachedLog();
    contents.emit("console-message", {}, 3, "Refused to frame 'http://localhost:7778/'", 1, "app.js");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /renderer console \[error\]: Refused to frame/);
  });

  it("drops warnings, which are dominated by per-paint noise", () => {
    const { lines, contents } = attachedLog();
    contents.emit("console-message", {}, 2, "Rendering was performed in a subtree hidden by content-visibility.", 1, "a.js");
    contents.emit("console-message", {}, 1, "just info", 1, "a.js");
    assert.deepEqual(lines, [], "only errors belong in the launch log");
  });

  it("caps identical repeats so one loud error cannot bury the load lines", () => {
    const { lines, contents } = attachedLog();
    for (let i = 0; i < 50; i += 1) {
      contents.emit("console-message", {}, 3, "same error", 1, "a.js");
    }
    assert.equal(lines.length, CONSOLE_REPEAT_LIMIT);
    assert.match(lines[CONSOLE_REPEAT_LIMIT - 1], /further repeats suppressed/);
    assert.doesNotMatch(lines[0], /further repeats suppressed/);
  });

  it("counts repeats per message, so a second distinct error still lands", () => {
    const { lines, contents } = attachedLog();
    for (let i = 0; i < 10; i += 1) contents.emit("console-message", {}, 3, "first", 1, "a.js");
    contents.emit("console-message", {}, 3, "second", 1, "a.js");
    assert.match(lines[lines.length - 1], /second/);
  });

  it("logs a started navigation and skips the SPA's in-place ones", () => {
    const { lines, contents } = attachedLog();
    contents.emit("did-start-navigation", {}, "http://localhost:7778/?token=s", false, false);
    contents.emit("did-start-navigation", {}, "http://localhost:5476/chat", true, true);
    assert.equal(lines.length, 1, "only the real navigation belongs in the log");
    assert.match(lines[0], /frame navigation STARTED \(subframe\)/);
  });

  it("keeps the dashboard's own [pane] journal even though it is INFO level", () => {
    const { lines, contents } = attachedLog();
    contents.emit(
      "console-message",
      {},
      1,
      `${PANE_LOG_PREFIX} load-timeout id=nobita frame=about:blank`,
      1,
      "app.js",
    );
    assert.equal(lines.length, 1, "the renderer half of the diagnosis must survive the filter");
    assert.match(lines[0], /load-timeout id=nobita frame=about:blank/);
  });

  it("gives the journal a higher repeat cap, because a re-mint loop IS the finding", () => {
    const { lines, contents } = attachedLog();
    for (let i = 0; i < PANE_REPEAT_LIMIT + 30; i += 1) {
      contents.emit("console-message", {}, 1, `${PANE_LOG_PREFIX} auth-expired id=nobita`, 1, "a.js");
    }
    assert.equal(lines.length, PANE_REPEAT_LIMIT);
    assert.ok(PANE_REPEAT_LIMIT > CONSOLE_REPEAT_LIMIT, "a loop needs more than three lines to be visible");
    assert.match(lines[PANE_REPEAT_LIMIT - 1], /further repeats suppressed/);
  });

  it("still drops a non-prefixed info line, so pane logs are not a blanket opening", () => {
    const { lines, contents } = attachedLog();
    contents.emit("console-message", {}, 1, "pane something not ours", 1, "a.js");
    assert.deepEqual(lines, []);
  });

  it("is inert rather than throwing when there is nothing to attach to", () => {
    assert.equal(attachFrameLoadLogging(null, () => {}), false);
    assert.equal(attachFrameLoadLogging({}, () => {}), false);
    assert.equal(attachFrameLoadLogging(fakeContents(), null), false);
  });
});
