#!/usr/bin/env node
/**
 * What `dist/` was built from, recorded at build time and checkable afterwards.
 *
 * `dist/` is what npm publishes. `package.json` ships `dist/` and not `src/`,
 * so the bytes in `dist/` ARE the scanner every user runs, and nothing in this
 * repository recorded which source they came from.
 *
 * That is not hypothetical here either. 1.4.0 was published against a gate that
 * read "the provenance check passes", and no such check existed in this
 * repository: it was satisfied by hand, with a clean-room clone and a
 * `diff -rq`. That worked, and it is not a control. The sibling repository has
 * had this file since `dist/` drifted onto an unmerged proposal twice in one
 * night, both times caught by eye.
 *
 * Two entry points:
 *
 *   node tools/provenance.js stamp    write dist/.provenance.json (build step)
 *   node tools/provenance.js check    verify it, exit non-zero if it is wrong
 *
 * `check --release` additionally refuses a build made from uncommitted or
 * unmerged source, which is the gate for publishing and for anything that
 * quotes a number.
 *
 * The stamp ships inside the tarball on purpose. `dist/.provenance.json` in an
 * installed copy answers "which commit is this scanner" without a checkout,
 * which is the same question a user asks when a finding looks wrong.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "src");
const DIST = path.join(ROOT, "dist");
const STAMP = path.join(DIST, ".provenance.json");

/** Every .ts file under src/, sorted, so the hash is stable across platforms. */
function sourceFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".ts")) out.push(full);
    }
  };
  walk(SRC);
  return out.sort();
}

/**
 * Hash of the source tree: every path and every byte.
 *
 * Paths are included, and relative with forward slashes, so that a renamed file
 * changes the hash and a Windows checkout produces the same digest as a mac
 * one. Content is hashed raw rather than line-normalised: a lone CR inside a
 * string literal is a real difference to the compiler.
 */
function sourceHash() {
  const h = crypto.createHash("sha256");
  for (const f of sourceFiles()) {
    h.update(path.relative(ROOT, f).split(path.sep).join("/"));
    h.update("\0");
    h.update(fs.readFileSync(f));
    h.update("\0");
  }
  return h.digest("hex");
}

function git(args, fallback) {
  try {
    return execFileSync("git", args, {
      cwd: ROOT, encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return fallback;
  }
}

/** True when src/ has uncommitted changes. Only src/ matters: docs do not build. */
function srcDirty() {
  const status = git(["status", "--porcelain", "--", "src"], null);
  if (status === null) return null;
  return status.length > 0;
}

function stamp() {
  if (!fs.existsSync(DIST)) {
    console.error("provenance stamp: dist/ does not exist. Run tsc first.");
    process.exit(1);
  }
  const record = {
    sourceHash: sourceHash(),
    commit: git(["rev-parse", "HEAD"], null),
    branch: git(["rev-parse", "--abbrev-ref", "HEAD"], null),
    dirty: srcDirty(),
    builtAt: new Date().toISOString(),
    node: process.version,
  };
  fs.writeFileSync(STAMP, JSON.stringify(record, null, 2) + "\n");
  console.log(describe(record, null));
}

/** Is `commit` an ancestor of `ref`? null when it cannot be determined. */
function mergedInto(commit, ref) {
  if (!commit) return null;
  if (git(["rev-parse", "--verify", "--quiet", ref], null) === null) return null;
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", commit, ref], {
      cwd: ROOT, timeout: 5000, stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function describe(record, actualHash) {
  const short = record.commit ? record.commit.slice(0, 7) : "unknown";
  const state = record.dirty === true ? ", uncommitted changes" : record.dirty === null ? ", git unavailable" : "";
  const match = actualHash === null ? "" : actualHash === record.sourceHash ? " [matches src]" : " [DOES NOT MATCH src]";
  return `dist built from ${short} on ${record.branch || "unknown"}${state}${match}`;
}

function check(release) {
  const problems = [];

  if (!fs.existsSync(STAMP)) {
    console.error(
      "dist/.provenance.json is missing, so what dist/ was built from is unknown.\n" +
        "This is a failure, not a default: an unstamped dist is exactly the state\n" +
        "the stamp exists to make impossible. Run: npm run build"
    );
    process.exit(1);
  }

  let record;
  try {
    record = JSON.parse(fs.readFileSync(STAMP, "utf8"));
  } catch (e) {
    console.error("dist/.provenance.json is unreadable: " + e.message + "\nRun: npm run build");
    process.exit(1);
  }

  const actual = sourceHash();
  if (actual !== record.sourceHash) {
    problems.push(
      "dist/ does not match src/. It was built from different source than the\n" +
        "  tree now on disk, so every suite that loads dist/ is testing bytes\n" +
        "  nobody is reading. Run: npm run build"
    );
  }

  if (release) {
    if (record.dirty === true) {
      problems.push("dist/ was built from a tree with uncommitted changes in src/.");
    }
    const merged = mergedInto(record.commit, "origin/main");
    if (merged === false) {
      problems.push(
        "dist/ was built from " + String(record.commit).slice(0, 7) + ", which is not an\n" +
          "  ancestor of origin/main. That is an unmerged proposal, and a number\n" +
          "  measured against it is not a number about the shipped guard."
      );
    }
  }

  console.log(describe(record, actual));
  if (record.commit) {
    const merged = mergedInto(record.commit, "origin/main");
    if (merged === false) console.log("  note: this commit is NOT merged into origin/main");
    else if (merged === true) console.log("  merged into origin/main");
  }

  if (problems.length) {
    console.error("\ndist provenance check FAILED:");
    for (const p of problems) console.error("- " + p);
    process.exit(1);
  }
}

const mode = process.argv[2];
if (mode === "stamp") stamp();
else if (mode === "check") check(process.argv.includes("--release"));
else {
  console.error("usage: node tools/provenance.js stamp | check [--release]");
  process.exit(2);
}
