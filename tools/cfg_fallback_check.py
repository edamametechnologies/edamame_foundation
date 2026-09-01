#!/usr/bin/env python3
"""cfg_fallback_check.py -- catch permissive `#[cfg(...)]` fallbacks.

A `#[cfg]`-gated arm that substitutes a bare `true`/`false` for a
security-relevant binding is a fail-open waiting to happen: the check silently
stops applying on every build where the feature is off, with no compile error
and no runtime log.

This is not hypothetical. `flodbadd/src/whitelists.rs` guarded two calls to
`is_reverse_dns_pattern` -- a PURE string helper that happened to live in the
`packetcapture`-gated `sni` module -- like this:

    #[cfg(not(feature = "packetcapture"))]
    let domain_is_reverse_pattern = false;   // CDN reverse-DNS skip disabled
    #[cfg(not(feature = "packetcapture"))]
    let use_domain = true;                   // every reverse-DNS name trusted

`edamame_core` enables `flodbadd/packetcapture` only via its `standalone`
feature, so the default build -- the one the EDAMAME app ships -- had both
guards dead. Generated whitelists accepted per-edge-IP CDN names such as
`cdn-185-199-110-133.github.com`, which cannot match the next time the CDN
answers from a different edge IP.

What this flags: any `#[cfg(...)]` attribute (positive OR negative -- the
permissive value can sit on either side) immediately followed by a bare bool
assignment to a binding whose name reads like a security predicate.

What it does NOT flag: "capability absent -> return empty/false" stubs, which
fail CLOSED. `Vec::new()` for "no sessions captured" asserts nothing.

Usage:
    tools/cfg_fallback_check.py            # exit 1 on any new finding
    tools/cfg_fallback_check.py --list     # print findings incl. baselined
    tools/cfg_fallback_check.py --json     # machine-readable

Baseline: known-safe sites live in BASELINE below, keyed by (file, binding,
value) rather than line number so they survive unrelated edits. Add an entry
ONLY with a reason explaining why the fallback is the conservative direction.

This file is kept identical across edamame_core, edamame_foundation and
flodbadd tools/ -- edit one, copy to the other two. The copy in edamame_core
scans the whole workspace (sibling checkouts are skipped when absent); the
copies in edamame_foundation and flodbadd scan only the repo they live in.
Baseline keys are `<package name>/<path>` so the same entry matches whichever
copy performs the scan.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Repos to scan, relative to this file's parent. The edamame_core copy scans
# the whole workspace (missing sibling repos are skipped with a note rather
# than failing -- not every checkout has all of them); the identical copies in
# edamame_foundation/ and flodbadd/ scan only themselves.
WORKSPACE_REPOS = [".", "../edamame_foundation", "../flodbadd"]
SELF_ONLY = ["."]


def repos_to_scan(repo_root: str) -> list[str]:
    if os.path.isfile(os.path.join(repo_root, "src", "core_manager.rs")):
        return WORKSPACE_REPOS
    return SELF_ONLY


_PACKAGE_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.M)


def repo_label(repo_root: str) -> str:
    """Stable label for baseline keys: the Cargo package name, so the key does
    not depend on the checkout directory name (CI may check out into a
    differently named directory)."""
    try:
        manifest = open(os.path.join(repo_root, "Cargo.toml"), encoding="utf-8").read()
    except OSError:
        return os.path.basename(repo_root)
    # First `name = "..."` is the [package] name; later ones are bins/examples.
    match = _PACKAGE_NAME.search(manifest)
    return match.group(1) if match else os.path.basename(repo_root)


# Bindings whose name reads like a security predicate. Deliberately broad: a
# false positive costs one baseline entry with a reason, a false negative costs
# a silent fail-open.
SECURITY_PREDICATE = re.compile(
    r"(^|_)("
    r"is|has|should|can|allow|allowed|trust|trusted|valid|verified|verif|"
    r"conform|conforms|safe|secret|sensitive|exempt|skip|suspicious|malicious|"
    r"blacklist|whitelist|sandbox|sandboxed|admin|root|priv|privileged|"
    r"enforce|enforced|require|required|signed|match|matched|reverse|pattern|"
    r"use|guard|dismiss|redact|mask|sanitized|policy|consent"
    r")($|_)"
)

CFG_ATTR = re.compile(r"^\s*#\[cfg\(")
BOOL_ASSIGN = re.compile(
    r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?::\s*bool\s*)?=\s*(true|false)\s*;"
)

# Known-safe fallbacks. Key: (repo-relative path, binding, value).
BASELINE: dict[tuple[str, str, str], str] = {
    (
        "edamame_core/src/core_manager_score.rs",
        "admin_status",
        "false",
    ): "Non-desktop targets have no admin concept; assuming NOT admin is the "
    "conservative direction (it can only lower the score, never raise it).",
    (
        "edamame_core/src/score_factory.rs",
        "admin_status",
        "false",
    ): "Same as core_manager_score.rs -- four sites in this file, all assuming "
    "NOT admin on non-desktop targets.",
}


def iter_rust_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in ("target", ".git", "tests", "benches")
        ]
        for name in filenames:
            if name.endswith(".rs") and name != "frb_generated.rs":
                yield os.path.join(dirpath, name)


def read_cfg_attribute(lines: list[str], start: int) -> tuple[str, int]:
    """Accumulate a possibly multi-line `#[cfg(...)]` attribute.

    Returns (normalised attribute text, index of its last line).
    """
    attr = lines[start].strip()
    end = start
    depth = attr.count("(") - attr.count(")")
    while depth > 0 and end + 1 < len(lines):
        end += 1
        attr += " " + lines[end].strip()
        depth = attr.count("(") - attr.count(")")
    return " ".join(attr.split()), end


def scan(repo_root: str, repo_label: str) -> list[dict]:
    findings = []
    for path in iter_rust_files(os.path.join(repo_root, "src")):
        try:
            lines = open(path, encoding="utf-8", errors="ignore").read().split("\n")
        except OSError:
            continue
        rel = os.path.join(repo_label, os.path.relpath(path, repo_root))
        rel = os.path.normpath(rel).replace(os.sep, "/")
        for i, line in enumerate(lines):
            if not CFG_ATTR.match(line):
                continue
            attr, end = read_cfg_attribute(lines, i)
            # `#[cfg(test)]` / `#[cfg(all(test, ...))]` arms are test-only and
            # cannot affect a shipped build.
            if re.search(r"\btest\b", attr):
                continue
            if end + 1 >= len(lines):
                continue
            match = BOOL_ASSIGN.search(lines[end + 1])
            if not match:
                continue
            binding, value = match.group(1), match.group(2)
            if not SECURITY_PREDICATE.search(binding):
                continue
            findings.append(
                {
                    "file": rel,
                    "line": end + 2,
                    "binding": binding,
                    "value": value,
                    "cfg": attr,
                }
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--list", action="store_true", help="print every finding, baselined included"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--require-repos",
        action="store_true",
        help="fail if any sibling repo is missing (full-workspace runs; CI checks "
        "out one repo at a time and should NOT pass this)",
    )
    args = parser.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)

    findings: list[dict] = []
    skipped: list[str] = []
    for repo in repos_to_scan(repo_root):
        root = os.path.normpath(os.path.join(repo_root, repo))
        if not os.path.isdir(os.path.join(root, "src")):
            skipped.append(os.path.basename(root))
            continue
        findings.extend(scan(root, repo_label(root)))

    for f in findings:
        f["baselined"] = (f["file"], f["binding"], f["value"]) in BASELINE

    new = [f for f in findings if not f["baselined"]]

    if args.json:
        print(json.dumps({"findings": findings, "skipped": skipped}, indent=2))
        return 1 if new else 0

    if skipped:
        print(f"note: skipped (not checked out): {', '.join(skipped)}\n")
        if args.require_repos:
            print(
                f"FAIL: --require-repos was passed but {len(skipped)} repo(s) are "
                f"missing, so this run does NOT cover the whole workspace."
            )
            return 1

    if args.list:
        for f in sorted(findings, key=lambda x: (x["file"], x["line"])):
            tag = "BASELINE" if f["baselined"] else "NEW"
            print(f"[{tag:8}] {f['file']}:{f['line']}")
            print(f"           let {f['binding']} = {f['value']};")
            print(f"           under {f['cfg'][:100]}")
        print()

    if not new:
        print(
            f"OK: {len(findings)} cfg bool fallback(s) on security-predicate "
            f"bindings, all baselined as conservative."
        )
        return 0

    print(f"FAIL: {len(new)} new cfg fallback(s) on security-predicate bindings.\n")
    for f in sorted(new, key=lambda x: (x["file"], x["line"])):
        print(f"  {f['file']}:{f['line']}")
        print(f"      let {f['binding']} = {f['value']};")
        print(f"      under {f['cfg'][:100]}")
    print(
        "\nEach of these silently stops applying on builds where the cfg is off.\n"
        "Fix by making the check unconditional -- if it depends on a helper stuck\n"
        "in a gated module, move the helper to an always-compiled one (see\n"
        "flodbadd/src/dns_patterns.rs). If the fallback really is the\n"
        "conservative direction, add it to BASELINE in this script with a reason."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
