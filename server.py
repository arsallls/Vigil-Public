#!/usr/bin/env python3
"""vigil self-hosted webhook receiver.

Your code never leaves your network. Runs the same scanner the Action runs, but
server-side - which also closes the hole where a PR rewrites the CI that grades
it, because the scanner no longer lives in the repo being scanned.

Stdlib only + git + openssl. A tool that reads hostile diffs should not drag in a
dependency tree to answer an HTTP request.
"""
import base64, hashlib, hmac, json, os, queue, shutil, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import report

HERE = os.path.dirname(os.path.abspath(__file__))
WANTED = {"opened", "synchronize", "reopened", "ready_for_review"}
_tokens = {}
# Bounded work queue. One org can be trusted to behave; an App anyone can install
# cannot. Full queue returns 503 and GitHub retries the delivery, which is a far
# better failure than the box running out of memory mid-scan.
WORK = queue.Queue(maxsize=int(os.environ.get("QUEUE_MAX", "256")))


def env(k, default=None):
    v = os.environ.get(k, default)
    if v is None:
        sys.exit(f"missing required env var {k}")
    return v


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# --- GitHub App auth ------------------------------------------------------------
def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def app_jwt():
    now = int(time.time())
    msg = (b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + b"." +
           b64(json.dumps({"iat": now - 60, "exp": now + 540,
                           "iss": env("VIGIL_APP_ID")}).encode()))
    # ponytail: openssl instead of PyJWT - one less dependency. Swap if you'd rather.
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                          env("VIGIL_PRIVATE_KEY_PATH")],
                         input=msg, capture_output=True, check=True).stdout
    return (msg + b"." + b64(sig)).decode()


def inst_token(inst_id):
    tok, exp = _tokens.get(inst_id, (None, 0))
    if tok and exp > time.time() + 120:
        return tok
    r = report.api("POST", f"/app/installations/{inst_id}/access_tokens", {}, app_jwt())
    _tokens[inst_id] = (r["token"], time.time() + 3000)   # GitHub issues them for 1h
    return r["token"]


# --- scanning -------------------------------------------------------------------
def scan_pr(repo, num, base_ref, token):
    """Fetch the PR's two endpoints and scan the diff. Nothing here is executed."""
    d = tempfile.mkdtemp(prefix="vigil-")
    try:
        url = f"https://x-access-token:{token}@github.com/{repo}.git"
        git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True,
                                        capture_output=True, timeout=300)
        subprocess.run(["git", "init", "-q", d], check=True, timeout=60)
        git("remote", "add", "origin", url)
        # ponytail: depth 200 contains the merge-base for virtually every PR.
        git("fetch", "-q", "--no-tags", "--depth=200", "origin",
            f"+refs/pull/{num}/head:refs/dg/head",
            f"+refs/heads/{base_ref}:refs/dg/base")
        git("checkout", "-q", "refs/dg/head")
        subprocess.run([sys.executable, f"{HERE}/scan.py",
                        "--base", "refs/dg/base", "--head", "refs/dg/head",
                        "--rules", f"{HERE}/rules.yaml",
                        "--json", os.path.join(d, "findings.json")],
                       cwd=d, capture_output=True, text=True, timeout=900)
        with open(os.path.join(d, "findings.json"), encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def handle(ev):
    pr, repo = ev["pull_request"], ev["repository"]["full_name"]
    num, head, base_ref = pr["number"], pr["head"]["sha"], pr["base"]["ref"]
    token = inst_token(ev["installation"]["id"])
    log(f"scanning {repo}#{num} @ {head[:7]}")
    try:
        res = scan_pr(repo, num, base_ref, token)
        state, desc = report.verdict_of(res)
    except Exception as e:                      # fail closed: never silently pass
        log(f"ERROR {repo}#{num}: {e!r}")
        report.set_status(repo, head, "error", f"vigil failed: {type(e).__name__}",
                          "", token)
        return
    # No tamper check here: the scanner is not in the repo, so the PR cannot touch it.
    render = lambda scans: report.render_comment(res, {
        "sha": head, "scans": scans,
        "run_url": f"https://github.com/{repo}/pull/{num}",
        "commit_url": f"https://github.com/{repo}/pull/{num}/commits/{head}"})
    action, cid, scans = report.upsert_comment(repo, num, render, token)
    report.set_status(repo, head, state, desc, "", token)
    log(f"{repo}#{num}: {state} ({res['count']} signals), comment {action} #{cid}, scan {scans}")


# --- http -----------------------------------------------------------------------
def worker():
    while True:
        ev = WORK.get()
        try:
            handle(ev)
        except Exception as e:                  # one bad event must not kill the worker
            log(f"worker error: {e!r}")
        finally:
            WORK.task_done()


def verify(secret, body, header):
    """Constant-time webhook signature check. Everything depends on this."""
    if not header:
        return False
    return hmac.compare_digest(
        "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest(), header)


class Hook(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, msg):
        b = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.reply(200, "ok") if self.path == "/healthz" else self.reply(404, "no")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 8_000_000:
            return self.reply(413, "too large")
        body = self.rfile.read(n)
        if not verify(env("VIGIL_WEBHOOK_SECRET").encode(), body,
                      self.headers.get("X-Hub-Signature-256")):
            log("rejected: bad signature")
            return self.reply(401, "bad signature")

        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            return self.reply(200, "pong")
        if event != "pull_request":
            return self.reply(204, "")
        ev = json.loads(body)
        if ev.get("action") not in WANTED:
            return self.reply(204, "")

        # GitHub wants a fast 2xx; scanning takes seconds to minutes.
        try:
            WORK.put_nowait(ev)
        except queue.Full:
            log(f"queue full, shedding {ev['repository']['full_name']}#{ev['pull_request']['number']}")
            return self.reply(503, "busy, retry")   # GitHub redelivers
        self.reply(202, "accepted")

    def log_message(self, *a):
        pass    # our own log() is enough


def selftest():
    s = b"shhh"
    body = b'{"zen":"x"}'
    good = "sha256=" + hmac.new(s, body, hashlib.sha256).hexdigest()
    assert verify(s, body, good)
    flip = good[:-1] + ("1" if good[-1] == "0" else "0")
    assert not verify(s, body, flip)
    assert not verify(s, body, None)
    assert not verify(s, body, "")
    assert not verify(s, b'{"zen":"y"}', good)
    assert not verify(b"other", body, good)
    assert b64(b"\xff\xfe") == b"__4"
    q = queue.Queue(maxsize=2)
    q.put_nowait(1); q.put_nowait(2)
    try:
        q.put_nowait(3); raise AssertionError("queue should have been full")
    except queue.Full:
        pass
    print("server selftest ok")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    for k in ("VIGIL_APP_ID", "VIGIL_PRIVATE_KEY_PATH", "VIGIL_WEBHOOK_SECRET"):
        env(k)
    n = int(os.environ.get("WORKERS", "4"))
    for _ in range(n):
        threading.Thread(target=worker, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    log(f"vigil listening on :{port} with {n} worker(s), queue max {WORK.maxsize}")
    ThreadingHTTPServer(("0.0.0.0", port), Hook).serve_forever()
