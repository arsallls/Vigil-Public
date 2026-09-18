# Vigil

Scans PR diffs for **malicious capability**, not code quality. No style notes, no
refactor suggestions, no "consider extracting a helper". One question only:

> Did this PR gain the ability to run commands, phone home, or read credentials —
> and does the file it landed in have any business doing that?

## Two ways to run it

- **GitHub Action** — two workflow files, zero infrastructure. Start here.
- **Self-hosted** — you run a small webhook server; code never leaves your network
  and a PR structurally cannot tamper with the scanner. See [SELFHOST.md](SELFHOST.md).

## Install

**No secrets. No account. No configuration.** Two small files, both on your default
branch. `GITHUB_TOKEN` is minted automatically by Actions — there is nothing to set up.

`.github/workflows/vigil-scan.yml`:

```yaml
name: vigil-scan
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  scan:
    uses: arsallls/Vigil-Public/.github/workflows/reusable-scan.yml@v1
```

`.github/workflows/vigil-report.yml`:

```yaml
name: vigil-report
on:
  workflow_run:
    workflows: [vigil-scan]
    types: [completed]
jobs:
  report:
    uses: arsallls/Vigil-Public/.github/workflows/reusable-report.yml@v1
    secrets: inherit
```

That is the whole install. Nothing is vendored into your repo — the reporter checks
out the tool's own code, so upgrades arrive by moving the `@v1` tag.

Optional inputs on the scan job: `exclude` (space-separated globs) and `fail-at`.

Then make the `vigil` status a required check in branch protection, or it stays
advisory.

## Why two workflows

On `pull_request` from a fork, `GITHUB_TOKEN` is read-only — it cannot comment.
The usual "fix" is `pull_request_target`, which runs fork-authored code with your
secrets and a write token. That *is* the vulnerability this tool scans for.

So the work is split:

| | trigger | token | touches PR code |
|---|---|---|---|
| `vigil-scan` | `pull_request` | read-only, no secrets | yes |
| `vigil-report` | `workflow_run` | `pull-requests: write` | **never** — reads one JSON artifact |

The privileged half runs base-branch code and parses a JSON file. That boundary is
the entire security model; don't collapse it for convenience.

## Trust model

The repo owner installs it. PR authors install nothing and cannot opt out.

One caveat that matters: on `pull_request`, GitHub runs the workflow file **as it
exists in the PR**, so a fork can edit the scanner that judges it. Three owner-side
controls close that, all free:

1. **Make `vigil` a required status check.** Delete the scan workflow and no
   status is ever posted — the PR sits blocked, not passed. Fails closed.
2. **Actions → "Require approval for all external contributors."** Nothing runs
   until a maintainer clicks. Default for first-time contributors on public repos.
3. **The reporter checks for CI tampering itself** — trusted side, via the API, so
   the PR cannot influence it. A PR touching `.github/workflows/`, `.github/actions/`,
   `.github/vigil/` or `action.yml` is judged by who wrote it:

   | author | result |
   |---|---|
   | fork, or not OWNER/MEMBER/COLLABORATOR | hard failure — the scan proves nothing |
   | maintainer with write access | a note; the verdict stands |

   A maintainer editing their own CI is maintenance, not an attack. Failing those
   would make every CI change red and teach people to ignore the check.

Without #1 this is advisory only. With it, the three failure modes — clean, flagged,
and scanner-neutered — all end in a merge block except clean.

## Bot identity (optional, cosmetic)

Skip this. It changes the comment's author from `github-actions[bot]` to your own
name and avatar, and changes nothing else. Every secret vigil mentions exists
only for this.

If you want it anyway, register a **GitHub App** — with **no webhook URL**. It is an
identity, not a service; nothing is hosted.

1. github.com/settings/apps/new. Permissions: `pull requests: write`,
   `commit statuses: write`, `contents: read`. No webhook, no events.
2. Install it on the repos you want scanned. Generate a private key.
3. Set repo secrets `VIGIL_APP_ID` and `VIGIL_APP_PRIVATE_KEY`, and repo
   variable `VIGIL_APP=true`.

The reporter mints an installation token at run time and posts as `vigil[bot]`.

**Per-repo cost:** the App private key lives in each consuming repo's secrets. For
more than a couple of repos, put it in **organisation** secrets scoped to all repos
and set the `VIGIL_APP` org variable — then per-repo setup returns to zero.
Personal accounts have no org-level secrets; a free org is the workaround.

**Distribution limit:** you cannot hand third parties your App's private key. A bot
identity across repos you do not own needs a hosted App holding the key centrally —
the one part of this design that requires a server. The scanner itself never does.

## What it detects

| family | examples |
|---|---|
| auto-exec hooks | npm `postinstall`, VS Code `runOn: folderOpen`, devcontainer `postCreateCommand`, `setup.py` `cmdclass` |
| CI tampering | `pull_request_target`, expression injection, `toJSON(secrets)`, `curl \| sh` |
| dynamic execution | `eval`, `new Function`, `child_process`, `os.system`, `shell=True`, `pickle.loads` |
| obfuscation | decode→exec chains, zero-width/bidi Unicode, 400+ char lines, high-entropy blobs |
| credential access | `~/.ssh/id_*`, `.aws/credentials`, `.npmrc`, keychain, browser `Local State`, `wallet.dat` |
| egress | hardcoded IP endpoints, paste/tunnel hosts, URL-sourced dependencies |
| reverse shells | `/dev/tcp/`, `nc -e`, `bash -i >&`, socket+connect shapes |

Severity is **capability × path class**. The same `postinstall` scores higher in a
PR titled "fix README typo" than in one touching build config, because capability
showing up where it has no business is the actual attack shape.

## Local use

```bash
python3 scan.py --base origin/main --rules rules.yaml
```

`--selftest` on either script runs its assertions. `--json PATH` emits the machine
format the reporter consumes.

## Suppression

Trailing `vigil: ok <reason>` on a line silences it. Line-level only by design —
a repo-wide ignore file is how these tools quietly stop working.

## Scanning this repo

vigil runs on its own PRs. `rules.yaml` and `*.md` are excluded, because in
this repo those files carry attack patterns as data and would flag the tool for
being the tool. Keep attack literals out of comments in scanned files — the
scanner cannot tell prose from code, and it is right not to try.

## Roadmap

Vigil today is a **free, zero-infrastructure GitHub Action** — deterministic, no LLM,
runs in your CI in seconds. That is deliberately the whole product for now.

If it proves useful, the planned next step is a **hosted Vigil App**: a one-click
GitHub App install with no workflow files and a real `vigil[bot]` posting the review —
the Greptile / CodeRabbit model, but focused solely on malicious capability rather than
code quality. The Action stays free and maintained regardless; the App would just be the
"I don't want to manage two workflow files" convenience layer.

Whether that gets built depends on whether people actually use and want it. If Vigil is
useful to you, a star or an issue describing your use case is the signal that decides it.

## Not a replacement for

[Socket](https://socket.dev) (dependency supply chain), [zizmor](https://github.com/woodruffw/zizmor)
(deep GitHub Actions auditing), Dependabot, or human review. Compose, don't replace.
