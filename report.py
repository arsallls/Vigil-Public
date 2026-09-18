#!/usr/bin/env python3
"""vigil reporter - the PRIVILEGED half.

Runs from the base branch via workflow_run. Never executes PR code; it only reads
the JSON the unprivileged scan produced. Posts one sticky comment and one commit
status. Stdlib only - a security tool should not pull a dependency tree to POST.
"""
import argparse, json, os, re, sys, urllib.error, urllib.request

API = "https://api.github.com"
MARK = "<!-- vigil:sticky"
HANDOFF_MARK = "<!-- vigil:handoff -->"


def handoff_body(res, mention, skipped):
    """Trigger comment for the downstream LLM reviewer. `skipped` True = Vigil
    found something critical and is NOT spending the reviewer (human can override)."""
    if skipped:
        return (f"{HANDOFF_MARK}\n{mention} was **not** auto-triggered: Vigil flagged "
                f"critical capability ({res['count']} signal(s), max {res['max_sev']}/4), "
                f"so this PR is blocked pending human review. Comment {mention} to run the "
                "deep review anyway.")
    focus = "; ".join(f"`{f['rule']}` at {f['path']}:{f['line']}"
                      for f in res["findings"][:3]) or "no capability signals"
    return (f"{HANDOFF_MARK}\n{mention} - Vigil pre-screen complete "
            f"({res['count']} signal(s)). Focus areas: {focus}. Full context in the "
            "comment above.")
MARKRX = __import__("re").compile(r"<!-- (?:vigil|diffguard):sticky(?: scans=(\d+))? -->")

BADGE = {1: ("P3", "note", "blue"), 2: ("P2", "review", "yellow"),
         3: ("P1", "high", "orange"), 4: ("P0", "critical", "red")}


def banner(res):
    """(emoji, verdict, headline). A capability verdict - not a safety fraction.
    Malicious code is not '2/5 safe'; it either introduces dangerous capability or not."""
    f = res.get("findings", [])
    if not f:
        return "\U0001F7E2", "Clear", "No malicious capability introduced by this diff."
    if res.get("verdict") == "clean":
        return ("\U0001F7E1", "Signals \u2014 informational",
                "Low-severity signals only. Nothing here grants dangerous capability.")
    head = {2: "New capability introduced. A maintainer should confirm why these lines exist.",
            3: "Dangerous capability in this diff. Do not merge until it is explained.",
            4: "Capability landed where it has no business being. "
               "Treat as hostile until proven otherwise."}
    return "\U0001F534", "Blocked", head.get(res.get("max_sev", 4), head[4])
FAMILY = {"npm-install-hook": "auto-exec", "vscode-autorun-task": "auto-exec", "editor-exec-path": "auto-exec",
          "devcontainer-lifecycle-command": "auto-exec", "python-install-hook": "auto-exec",
          "workflow-pull-request-target": "ci-tampering",
          "workflow-expression-injection": "ci-tampering",
          "workflow-secret-sweep": "ci-tampering", "curl-pipe-shell": "ci-tampering",
          "js-dynamic-exec": "dynamic-exec", "py-dynamic-exec": "dynamic-exec",
          "js-decode-to-exec": "obfuscation", "py-decode-to-exec": "obfuscation",
          "invisible-unicode": "obfuscation", "off-screen-line": "obfuscation",
          "opaque-blob": "obfuscation", "encoded-string": "obfuscation",
          "py-dynamic-resolution": "obfuscation", "encoded-decode-call": "obfuscation", "credential-store-access": "credential-access",
          "js-env-harvest": "credential-access", "py-env-harvest": "credential-access",
          "hardcoded-ip-egress": "egress", "suspicious-egress-host": "egress",
          "dependency-from-url": "egress", "reverse-shell-shape": "reverse-shell"}


TITLES = {
    "npm-install-hook": "npm install hook",
    "vscode-autorun-task": "Editor auto-run task",
    "editor-exec-path": "Editor executable-path override",
    "devcontainer-lifecycle-command": "Devcontainer lifecycle hook",
    "python-install-hook": "pip install hook",
    "workflow-pull-request-target": "pull_request_target trigger",
    "workflow-expression-injection": "Workflow expression injection",
    "curl-pipe-shell": "Remote script piped to shell",
    "workflow-secret-sweep": "Secrets context serialized",
    "js-dynamic-exec": "Dynamic execution",
    "py-dynamic-exec": "Dynamic execution",
    "js-decode-to-exec": "Decode-to-execute",
    "py-decode-to-exec": "Decode-to-execute",
    "credential-store-access": "Credential store access",
    "hardcoded-secret": "Hardcoded secret",
    "js-env-harvest": "Environment harvested",
    "py-env-harvest": "Environment harvested",
    "hardcoded-ip-egress": "Hardcoded IP endpoint",
    "suspicious-egress-host": "Paste / tunnel host egress",
    "dependency-from-url": "Dependency from URL",
    "reverse-shell-shape": "Reverse shell",
    "invisible-unicode": "Invisible Unicode",
    "off-screen-line": "Off-screen line",
    "opaque-blob": "Opaque blob",
    "prompt-injection": "Prompt injection",
    "stylesheet-active-content": "Stylesheet active content",
    "encoded-string": "Encoded string",
    "py-dynamic-resolution": "Dynamic resolution",
    "encoded-decode-call": "Encoded decode",
}


def pretty(rule):
    return TITLES.get(rule) or rule.replace("-", " ").replace("_", " ").capitalize()


def agent_prompt(findings):
    lines = [f"- {f['path']}:{f['line']}  ({f['rule']}: {f['msg'].rstrip('.')})"
             for f in findings[:12]]
    return ("Investigate these lines flagged by Vigil in this pull request.\n\n"
            + "\n".join(lines)
            + "\n\nFor each one, explain exactly what it does at runtime, what data it "
              "reads, and where that data goes. Check whether the PR description justifies "
              "it.\nReport only - do not modify or 'fix' anything. If a line is benign, say "
              "why in one sentence so it can be suppressed with `vigil: ok <reason>`.")


def render_comment(res, meta):
    """Rich sticky-comment body. Terminal output stays plain - different audiences."""
    f = res["findings"]
    L = []
    if not f and not res["files_changed"] and res.get("files_excluded"):
        return ("## Nothing scanned\n\nAll "
                f"{res['files_excluded']} changed file(s) are excluded by configuration. "
                "No judgement is being made about this diff.\n\n"
                f"<sub>Scans ({meta['scans']}) &middot; commit <code>{meta['sha'][:7]}</code></sub>")
    if res.get("tamper"):
        L += [TAMPER.format(res["tamper"]), ""]
    elif res.get("ci_note"):
        L += [CI_NOTE.format(res["ci_note"]), ""]
    emoji, word, head = banner(res)
    if res.get("tamper"):
        emoji, word, head = "\U0001F534", "Blocked", "CI configuration was altered by this diff (see above)."
    L += [f"## {emoji} {word}", "", head, ""]
    if f:
        caps = sorted({FAMILY.get(x["rule"], "other") for x in f})
        L += ["**Capabilities detected:** " + " ".join(f"`{c}`" for c in caps), ""]

    if f:
        # group by file, worst file first, and collapse a rule repeated in one file
        byfile = {}
        for x in f:
            byfile.setdefault(x["path"], []).append(x)
        order = sorted(byfile, key=lambda p: (-max(y["sev"] for y in byfile[p]), p))

        worst = f[0]
        # the message already opens with the rule's own name - don't say it twice
        lead = worst["msg"].rstrip(".")
        L += [f"**Start with `{worst['path']}:{worst['line']}`** &mdash; "
              f"{lead[0].upper() + lead[1:]}.", "", "### Findings", ""]

        for path in order:
            rows, seen = byfile[path], {}
            for x in rows:
                k = (x["sev"], pretty(x["rule"]))
                seen.setdefault(k, []).append(x["line"])
            top = max(y["sev"] for y in rows)
            L += [f"<b>{path}</b> &nbsp;<sub>{len(rows)} signal(s), "
                  f"highest {BADGE[top][1]}</sub>", ""]
            for (sev, title), lines in sorted(seen.items(), key=lambda kv: -kv[0][0]):
                p, label, color = BADGE[sev]
                where = "line " + ", ".join(str(n) for n in sorted(set(lines))[:6])
                L.append(f"- ![{label}](https://img.shields.io/badge/{p}-{label}-{color}"
                         f"?style=flat-square) **{title}** &nbsp;<sub>{where}</sub>")
            L.append("")

        # explain each distinct rule once instead of under every occurrence
        uniq = {}
        for x in f:
            uniq.setdefault(pretty(x["rule"]), x["msg"])
        L += ["<details>", "<summary>What these mean</summary>", ""]
        L += [f"- **{t}** &mdash; {m}" for t, m in sorted(uniq.items())]
        L += ["", "</details>", "",
              "<details>", "<summary>Investigate with agent prompt</summary>", "",
              "```text", agent_prompt(f), "```", "", "</details>", ""]

    L += ["<details>", "<summary>Summary</summary>", ""]
    L += [f"Scanned **{res['files_changed']}** changed file(s) for malicious capability - "
          "auto-exec hooks, CI tampering, dynamic execution, obfuscated payloads, "
          "credential access, and egress. This is not a code-quality review.", ""]
    if f:
        L += ["Findings are **capabilities, not verdicts**. A human decides. "
              "Suppress a known-good line with a trailing `vigil: ok <reason>` comment."]
    L += ["", "</details>", ""]

    sha7 = meta["sha"][:7]
    L.append(f"<sub>Scans ({meta['scans']}) &middot; Last scanned commit "
             f"<a href=\"{meta['commit_url']}\"><code>{sha7}</code></a> &middot; "
             f"<a href=\"{meta['run_url']}\">Rescan</a></sub>")
    return "\n".join(L)




def api(method, path, body=None, token=None):
    req = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json",
                 "User-Agent": "vigil"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or "null")


def find_sticky(repo, pr, token):
    """-> (comment_id, prior_scan_count). State lives in our own marker, not a database."""
    # ponytail: first page only. A PR with 100+ comments gets a second comment, not a crash.
    for c in api("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100", token=token) or []:
        m = MARKRX.search(c.get("body") or "")
        if m:
            return c["id"], int(m.group(1) or 1)
    return None, 0


def upsert_comment(repo, pr, render, token):
    """One comment per PR, edited in place. A fresh comment per push is how bots get muted."""
    cid, prior = find_sticky(repo, pr, token)
    scans = prior + 1
    body = f"{MARK} scans={scans} -->\n" + render(scans)
    if cid:
        api("PATCH", f"/repos/{repo}/issues/comments/{cid}", {"body": body}, token)
        return "updated", cid, scans
    new = api("POST", f"/repos/{repo}/issues/{pr}/comments", {"body": body}, token)
    return "created", new["id"], scans


GATE_PARTNERS = [("greptile.json", "@greptileai"),
                 (".coderabbit.yaml", "@coderabbitai"),
                 (".coderabbit.yml", "@coderabbitai")]


def _gate_waits(path, raw):
    """True if this partner config disables auto-review, so Vigil should trigger it
    after its pre-screen (otherwise mentioning it would double-run the reviewer).
    ponytail: greptile.json is real JSON; coderabbit yaml checked by a bounded regex
    (no yaml in stdlib) - swap in a parser if the heuristic ever misfires."""
    if path.endswith(".json"):
        try:
            return str(json.loads(raw).get("skipReview", "")).upper() == "AUTOMATIC"
        except (json.JSONDecodeError, AttributeError):
            return False
    return (re.search(r"auto_review:[\s\S]{0,120}?enabled:\s*false", raw, re.I) is not None
            or re.search(r"disable_auto_review:\s*true", raw, re.I) is not None)


def detect_gate(repo, token):
    """Partner reviewers this repo has configured to wait for Vigil -> their @mentions.
    Reads the default branch via the contents API, so a PR cannot inject a trigger."""
    import base64
    out = []
    for path, mention in GATE_PARTNERS:
        try:
            r = api("GET", f"/repos/{repo}/contents/{path}", token=token)
        except urllib.error.HTTPError:
            continue
        raw = base64.b64decode(r.get("content", "") or "").decode("utf-8", "replace")
        if _gate_waits(path, raw) and mention not in out:
            out.append(mention)
    return out


def post_handoff(repo, pr, body, token):
    """One handoff comment: delete any prior one so the fresh @mention re-triggers
    the reviewer (edits don't re-fire mentions)."""
    for c in api("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100", token=token) or []:
        if HANDOFF_MARK in (c.get("body") or ""):
            api("DELETE", f"/repos/{repo}/issues/comments/{c['id']}", token=token)
    api("POST", f"/repos/{repo}/issues/{pr}/comments", {"body": body}, token)


def set_status(repo, sha, state, desc, url, token):
    api("POST", f"/repos/{repo}/statuses/{sha}",
        {"state": state, "context": "Vigil", "description": desc[:140],
         "target_url": url}, token)


TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
CI_PATHS = (".github/workflows/", ".github/actions/", ".github/vigil/")


def ci_risk(repo, pr, token):
    """-> (workflow-ish files this PR touches, whether the author is trusted)

    `pull_request` runs the workflow file FROM THE PR's branch, so a fork can
    neuter the scanner and upload a fabricated clean result. This check runs on
    the trusted side against the API, so the PR cannot influence it.

    But a maintainer editing their own CI is maintenance, not an attack. Only an
    outside contributor doing it is the thing worth failing over - the same
    distinction GitHub makes when it gates fork workflow runs behind approval.
    """
    meta = api("GET", f"/repos/{repo}/pulls/{pr}", token=token) or {}
    head_repo = ((meta.get("head") or {}).get("repo") or {}).get("full_name")
    fork = head_repo != repo          # null head repo (deleted fork) counts as a fork
    trusted = not fork and meta.get("author_association") in TRUSTED
    # ponytail: first page. A PR touching 100+ files is already getting read by a human.
    files = api("GET", f"/repos/{repo}/pulls/{pr}/files?per_page=100", token=token) or []
    touched = [f["filename"] for f in files
               if f["filename"].startswith(CI_PATHS)
               or f["filename"] in ("action.yml", "action.yaml")]
    return touched, trusted


TAMPER = ("> [!CAUTION]\n"
          "> **This PR modifies the CI that reviews it, and the author is not a "
          "maintainer.** The scan result below was produced by workflow files this PR "
          "can rewrite, so it proves nothing.\n"
          "> Changed: {}\n\n")

CI_NOTE = ("> [!NOTE]\n"
           "> This PR changes vigil's own configuration. The author has write "
           "access, so the scan result stands - but review the CI diff on its own "
           "merits.\n"
           "> Changed: {}\n\n")


def verdict_of(r):
    """-> (status_state, one-line description)."""
    if r["count"] == 0 and not r["files_changed"] and r.get("files_excluded"):
        return "success", f"Nothing scanned - all {r['files_excluded']} changed file(s) excluded"
    if r["count"] == 0:
        return "success", f"Clean - no malicious-capability signals in {r['files_changed']} file(s)"
    if r["verdict"] == "clean":
        return "success", f"{r['count']} low-severity signal(s) - informational"
    return "failure", f"{r['count']} signal(s), highest: {BADGE[r['max_sev']][1]} - needs review"


def selftest():
    assert verdict_of({"count": 0, "verdict": "clean", "files_changed": 3, "max_sev": 0})[0] == "success"
    assert verdict_of({"count": 2, "verdict": "clean", "files_changed": 3, "max_sev": 2})[0] == "success"
    assert verdict_of({"count": 5, "verdict": "flagged", "files_changed": 3, "max_sev": 4})[0] == "failure"
    assert "critical" in verdict_of({"count": 5, "verdict": "flagged", "files_changed": 3, "max_sev": 4})[1]
    assert len(verdict_of({"count": 9, "verdict": "flagged", "files_changed": 99, "max_sev": 3})[1]) <= 140
    assert "CAUTION" in TAMPER.format("`.github/workflows/x.yml`")
    meta = {"sha": "a" * 40, "scans": 3, "run_url": "u", "commit_url": "c"}
    clean = render_comment({"findings": [], "max_sev": 0, "files_changed": 2}, meta)
    assert "Clear" in clean and "Findings" not in clean
    allx = render_comment({"findings": [], "max_sev": 0, "files_changed": 0,
                           "files_excluded": 2}, meta)
    assert "Nothing scanned" in allx and "Clear" not in allx
    assert verdict_of({"count": 0, "verdict": "clean", "files_changed": 0,
                       "max_sev": 0, "files_excluded": 2})[1].startswith("Nothing scanned")
    assert "Scans (3)" in clean
    bad = {"findings": [{"sev": 4, "rule": "credential-store-access", "path": "a.js",
                         "line": 4, "msg": "ssh key"}], "max_sev": 4, "files_changed": 1}
    r = render_comment(bad, meta)
    assert "Blocked" in r and "P0-critical-red" in r
    assert "Credential store access" in r and "credential-access" in r
    assert r.count("<details>") == r.count("</details>") == 3
    assert "Start with `a.js:4`" in r
    # lead must not repeat the rule title that the message already carries
    one = {"findings": [{"sev": 4, "rule": "hardcoded-ip-egress", "path": "r.txt",
                         "line": 1, "msg": "Hardcoded IP endpoint - use hostnames."}],
           "max_sev": 4, "files_changed": 1}
    lead = render_comment(one, meta).split("### Findings")[0]
    assert lead.count("Hardcoded IP endpoint") == 1, lead
    # same rule twice in one file collapses to one row listing both lines
    dup = {"findings": [{"sev": 3, "rule": "hardcoded-ip-egress", "path": "a.py",
                         "line": n, "msg": "ip"} for n in (7, 9)],
           "max_sev": 3, "files_changed": 1}
    d = render_comment(dup, meta)
    # one collapsed row + one explanation - NOT one row per hit
    assert d.count("Hardcoded IP endpoint") == 2
    assert d.count("![high]") == 1                    # two hits, one badge row
    assert "line 7, 9" in d
    bad["tamper"] = "`.github/workflows/x.yml`"
    assert "CAUTION" in render_comment(bad, meta)
    # a maintainer touching CI gets a note and keeps the verdict, not a failure
    ok = {"findings": [], "max_sev": 0, "files_changed": 1,
          "ci_note": "`.github/workflows/x.yml`"}
    r2 = render_comment(ok, meta)
    assert "NOTE" in r2 and "CAUTION" not in r2 and "Clear" in r2
    assert MARKRX.search("<!-- vigil:sticky scans=7 -->").group(1) == "7"
    assert MARKRX.search("<!-- diffguard:sticky scans=7 -->").group(1) == "7"  # legacy comments still matched
    assert MARKRX.search("<!-- vigil:sticky -->").group(1) is None
    r0 = {"findings": [{"rule": "py-decode-to-exec", "path": "a.py", "line": 5}],
          "count": 1, "max_sev": 3}
    assert _gate_waits("greptile.json", '{"skipReview":"AUTOMATIC"}')
    assert not _gate_waits("greptile.json", '{"skipReview":"OFF"}')
    assert not _gate_waits("greptile.json", "not json at all")
    assert _gate_waits(".coderabbit.yaml", "reviews:\n  auto_review:\n    enabled: false\n")
    assert not _gate_waits(".coderabbit.yaml", "reviews:\n  auto_review:\n    enabled: true\n")
    assert _gate_waits(".coderabbit.yml", "disable_auto_review: true")
    b = handoff_body(r0, "@greptileai", False)
    assert "@greptileai" in b and "py-decode-to-exec` at a.py:5" in b and HANDOFF_MARK in b
    bs = handoff_body({"findings": [], "count": 9, "max_sev": 4}, "@greptileai", True)
    assert "not" in bs and "blocked" in bs and "@greptileai" in bs
    print("report selftest ok")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default="_dg", help="artifact dir from the scan job")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()

    d = a.dir
    res = json.load(open(f"{d}/findings.json", encoding="utf-8"))
    pr = open(f"{d}/pr", encoding="utf-8").read().strip()
    sha = open(f"{d}/sha", encoding="utf-8").read().strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    url = os.environ.get("RUN_URL", "")

    state, desc = verdict_of(res)
    touched, trusted = [], True
    if token and not a.dry_run:
        try:
            touched, trusted = ci_risk(repo, pr, token)
        except urllib.error.HTTPError:
            touched, trusted = [], True
    if touched:
        names = ", ".join(f"`{f}`" for f in touched[:5])
        if trusted:
            res["ci_note"] = names          # informational; the verdict stands
        else:
            state = "failure"
            desc = (f"Outside contributor modifies CI ({len(touched)} file(s)) "
                    "- result untrusted")
            res["tamper"] = names
    render = lambda scans: render_comment(res, {
        "sha": sha, "scans": scans, "run_url": url,
        "commit_url": f"https://github.com/{repo}/pull/{pr}/commits/{sha}"})

    if a.dry_run or not token:
        print(f"[dry-run] repo={repo} pr={pr} sha={sha[:7]} status={state}\n{desc}\n"
              + "-" * 60 + "\n" + render(1))
        return 0

    try:
        action, cid, scans = upsert_comment(repo, pr, render, token)
        set_status(repo, sha, state, desc, url, token)
        print(f"comment {action} (id {cid}, scan #{scans}); status {state}: {desc}")
        # Gate is ON by default: auto-detect any partner reviewer this repo has set
        # to wait for Vigil. VIGIL_GATE forces specific @mentions; "off" disables.
        override = os.environ.get("VIGIL_GATE", os.environ.get("GREPTILE_MENTION", "")).strip()
        if override.lower() in ("off", "none", "false", "0"):
            mentions = []
        elif override:
            mentions = override.split()
        else:
            mentions = detect_gate(repo, token)
        if mentions:
            mention = " ".join(mentions)
            skip_at = int(os.environ.get("HANDOFF_SKIP_AT", "0") or "0")
            skipped = skip_at and res["max_sev"] >= skip_at
            post_handoff(repo, pr, handoff_body(res, mention, bool(skipped)), token)
            print(f"handoff: {'skipped (critical)' if skipped else 'triggered'} {mention}")
    except urllib.error.HTTPError as e:
        print(f"github api {e.code}: {e.read()[:300].decode(errors='replace')}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
