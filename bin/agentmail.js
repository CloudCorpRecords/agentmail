#!/usr/bin/env node
/**
 * agentmail launcher.
 *
 * With no arguments (or with --mcp) it starts the Agent Mail MCP server on
 * stdio, so agents like Claude Code or Cursor can use the mailbox as tools.
 * With arguments it runs the CLI: agentmail <command> [args].
 *
 * The Python client needs: python >= 3.10, and the `cryptography` and `httpx`
 * packages. A venv bundled with the install (python/.venv) wins if present,
 * then $AGENTMAIL_PYTHON, then `python3` on PATH.
 */
"use strict";

const { spawn, spawnSync } = require("node:child_process");
const { existsSync } = require("node:fs");
const { join } = require("node:path");

const ROOT = join(__dirname, "..");
const PYDIR = join(ROOT, "python");

function findPython() {
  const bundled = join(PYDIR, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python3");
  const candidates = [
    bundled,
    process.env.AGENTMAIL_PYTHON,
    "python3",
  ].filter(Boolean);
  for (const c of candidates) {
    if (c.includes("/") || c.includes("\\")) {
      if (existsSync(c)) return c;
    } else {
      return c; // on PATH, check below
    }
  }
  return "python3";
}

function fail(msg) {
  process.stderr.write(`agentmail: ${msg}\n`);
  process.exit(1);
}

const python = findPython();

// The Python tree must be present (it ships inside this package).
if (!existsSync(join(PYDIR, "agentmail_client", "__init__.py"))) {
  fail("the bundled Python client is missing. Reinstall @reneturcios/agentmail.");
}

// 1. Python version check.
{
  const r = spawnSync(python, ["-c", "import sys; print(sys.version_info[0]*100 + sys.version_info[1])"],
    { encoding: "utf8" });
  if (r.error || r.status !== 0) {
    fail(`could not run '${python}'. Install Python 3.10 or newer, or set AGENTMAIL_PYTHON to your Python.`);
  }
  const v = parseInt((r.stdout || "").trim(), 10);
  if (Number.isNaN(v) || v < 310) {
    fail(`needs Python 3.10 or newer (found ${v}). Set AGENTMAIL_PYTHON to a newer Python.`);
  }
}

// 2. Dependency check, naming exactly what is missing.
{
  const r = spawnSync(python, ["-c", "import cryptography, httpx; print('ok')"], { encoding: "utf8" });
  if (r.error || r.status !== 0 || !(r.stdout || "").includes("ok")) {
    const missing = [];
    for (const dep of ["cryptography", "httpx"]) {
      const q = spawnSync(python, ["-c", `import ${dep}`], { encoding: "utf8" });
      if (q.error || q.status !== 0) missing.push(dep);
    }
    fail(`missing Python dependenc${missing.length === 1 ? "y" : "ies"}: ${missing.join(", ") || "cryptography, httpx"}. ` +
      `Install with: ${python} -m pip install ${missing.join(" ") || "cryptography httpx"}`);
  }
}

const rawArgs = process.argv.slice(2);
const wantsMcp = rawArgs.length === 0 || rawArgs[0] === "--mcp";
const pyArgs = wantsMcp
  ? ["-m", "agentmail_client.mcp_server"]
  : ["-m", "agentmail_client", ...rawArgs];

const child = spawn(python, pyArgs, { cwd: PYDIR, stdio: "inherit" });
child.on("error", (e) => fail(`could not start the Python client: ${e.message}`));
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code === null ? 1 : code);
});
