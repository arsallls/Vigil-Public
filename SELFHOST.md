# Self-hosting vigil

Your code never leaves your network. GitHub sends a webhook; your box does the
scanning and posts the result back. Nothing is sent to a third party.

This also closes a hole the GitHub Action version cannot: because the scanner no
longer lives in the repo being scanned, a PR cannot rewrite the CI that grades it.

## 1. Register a GitHub App

github.com/settings/apps/new (or your org's settings for an org-wide install).

| Field | Value |
|---|---|
| Webhook URL | your public HTTPS endpoint (see step 3) |
| Webhook secret | `openssl rand -hex 32` — keep it |
| Repository permissions | Pull requests: **Read & write**<br>Commit statuses: **Read & write**<br>Contents: **Read-only**<br>Metadata: **Read-only** |
| Subscribe to events | **Pull request** |

Generate a private key, download the `.pem`, then install the App on the repos or
org you want scanned. Note the App ID.

## 2. Configure

```bash
cp vigil.private-key.pem ./vigil.private-key.pem
chmod 600 vigil.private-key.pem
cat > .env <<'ENV'
VIGIL_APP_ID=123456
VIGIL_WEBHOOK_SECRET=the-hex-string-from-step-1
ENV
docker compose up -d --build
```

Verify: `curl localhost:8080/healthz` → `ok`.

## 3. Give GitHub a way in

The container binds to **127.0.0.1 only** — deliberately. Choose one:

- **Cloudflare Tunnel** (no open ports, free): `cloudflared tunnel --url http://localhost:8080`
- **Reverse proxy** with TLS: Caddy or nginx to `127.0.0.1:8080`
- **Tailscale Funnel** if you already run Tailscale

Put the resulting HTTPS URL in the App's Webhook URL field. GitHub's "Redeliver"
button on a past delivery is the fastest way to test without opening a PR.

## 4. Make it enforcing

Branch protection → require the `vigil` status check. Without this the scan is
advisory and a merge can ignore it.

## Security properties

| | |
|---|---|
| Webhook auth | HMAC-SHA256 over the raw body, constant-time compare. Unsigned requests are rejected before parsing. |
| PR code | Fetched and **parsed**, never executed. No install, no build, no test run. |
| Isolation | Non-root user, read-only root filesystem, all capabilities dropped, clones in tmpfs, memory and PID limits. |
| Failure mode | Fails **closed** — a scan that errors posts an `error` status rather than staying silent. |
| Secrets | The App private key is mounted read-only and never leaves the container. |

## Scaling

One box handles a lot; scanning is seconds per PR. The known ceiling is in
`server.py`: webhook handling spawns an in-process thread with no queue, so a
restart drops in-flight scans and a burst is bounded by memory. Add a real queue
when that actually bites — GitHub retries failed deliveries, and the status check
fails closed meanwhile.

## Hosting it for other people

Everything above assumes you run this for your own repos. To let *anyone* install
your bot, three App settings change — the code does not:

| setting | self-host | hosted for others |
|---|---|---|
| Where can this be installed | Only on this account | **Any account** |
| Webhook → Active | unchecked | **checked**, pointing at your URL |
| Uptime | best effort | yours to own |

`server.py` is already multi-tenant: it reads `installation.id` from each event and
mints a token scoped to that installation, so one process serves every installer
without changes.

**What adopters then do:** click Install. No workflow files, no secrets, no config.
That is the whole pitch, and it is only reachable this way — a GitHub App is the
only mechanism that carries *your* bot identity onto someone else's repo.

### What you are taking on

- **An always-on box.** Down means no status posts. If adopters made the check
  required, their merges block until you are back.
- **Other people's source code** transiently on your disk. Anyone installing on a
  private repo is trusting you with it. Say plainly what you retain (this retains
  nothing — clones are deleted in a `finally`, and tmpfs never touches disk).
- **Abuse capacity.** The queue sheds load at `QUEUE_MAX` and GitHub retries, but
  a determined installer can still burn your CPU. Rate-limit per installation
  before you advertise.
- **A support surface.** Every adopter's broken scan becomes your issue tracker.

None of it is hard. It is just the difference between shipping a tool and running
a service, and it is worth deciding deliberately rather than drifting into it.

## Which deployment do I want?

| | GitHub Action | Self-hosted | Hosted for others |
|---|---|---|---|
| Infra | none | one small box | one box, always on |
| Adopter install | 2 workflow files | 2 files + your server | **one click, nothing else** |
| Adopter needs secrets | only for own branding | no | **no** |
| Whose code is on the box | n/a | yours | **theirs** |
| PR can tamper with the scanner | detected, not prevented | no | no |
| Your bot identity on their repo | impossible | impossible | **yes** |
| Who is on the hook at 3am | nobody | you | you, for everyone |

Start with the Action. Move here when you want org-wide install, or when "a PR
cannot touch the scanner" needs to be structurally true rather than checked.

## Gating an LLM reviewer behind Vigil (e.g. Greptile)

Run Vigil first, free and deterministic, then trigger the LLM reviewer with Vigil's
findings as focus context - and optionally skip the LLM entirely on a critical hit.

**Two parts, both required:**

1. **Reviewer side** - stop it auto-running. For Greptile, add to `greptile.json`:
   ```json
   { "skipReview": "AUTOMATIC" }
   ```
   Now it reviews only when a comment mentions `@greptileai`.

2. **Vigil side** - set repo variables:
   - `GREPTILE_MENTION` = `@greptileai` (enables the handoff; empty = off)
   - `HANDOFF_SKIP_AT` = `4` (optional: if Vigil's max severity >= this, block and do
     NOT spend the reviewer - a human can still trigger it)

Vigil then posts its findings, then a fresh `@greptileai` comment carrying the top
signals. Prior handoff comments are deleted first so the mention re-fires on each push.

**Fail-open warning.** With `skipReview: AUTOMATIC`, the reviewer runs ONLY when
triggered. If Vigil's workflow fails to run (Actions outage, a semgrep install flake,
a bad rule), nothing triggers the reviewer and the PR silently gets no deep review.
The human `@greptileai` fallback still works, so a failure degrades to "manual
trigger", not "no review ever" - but do not treat the gate as guaranteed delivery.
