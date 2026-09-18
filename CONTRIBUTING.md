# Contributing to Vigil

Vigil is a deterministic scanner for **malicious capability** in pull-request diffs —
no LLM, no code-quality opinions. Contributions that keep it fast, deterministic, and
low-false-positive are very welcome.

## Ground rules

- **Standard library only.** `scan.py` and `report.py` import nothing outside the Python
  stdlib (the runtime installs `semgrep` separately). Don't add pip dependencies.
- **The scanner is deterministic and offline.** `scan.py` must produce the same verdict
  for the same diff, with no network. API calls live only in the reporter (`report.py`).
- **Every rule ships a test.** A detection that isn't covered by an assertion will rot.

## Project layout

| file | what it is |
|---|---|
| `scan.py` | the scanner — lexical regex rules on added diff lines + a semgrep pass |
| `rules.yaml` | the semgrep (AST) rules |
| `report.py` | posts the sticky comment, the status check, and the reviewer handoff |
| `test_coverage.py` | builds a fixture PR that must trip every rule |

## Running the checks

```bash
python3 scan.py --selftest      # lexical rules + injection recall/FP assertions
python3 report.py --selftest    # rendering, verdict, and gate-parser assertions
python3 test_coverage.py        # every rule fires on the fixture (needs semgrep)
```

Install semgrep for the full run: `pipx install semgrep` (or `pip install semgrep`).

## Adding a detection

Two kinds:

- **Lexical** (regex on added lines) — for things that hide in prose, comments, CSS,
  config, or across languages: prompt injection, invisible Unicode, encoded blobs. Add the
  pattern in `scan.py` and, in its `selftest()`, **both a positive and a benign negative** —
  so it catches the attack without flagging normal code.
- **Semantic** (semgrep) — for code shapes: `eval`, `child_process`, install hooks, reverse
  shells. Add the rule to `rules.yaml` and extend `test_coverage.py` so the fixture trips it.

### False positives are the bug that kills adoption

A scanner that flags clean PRs gets switched off. New rules are judged on **precision**,
not just recall. Before opening a PR, run your rule against real benign code — a few of
your own repos' diffs — and confirm it stays quiet. If a pattern is inherently noisy,
scope it by path or context instead of firing everywhere. When in doubt, go **narrow**.

## Reporting a bypass or security issue

If you've found a way to sneak malicious capability past Vigil, **do not open a public
issue** — that's a live evasion recipe. Report it privately through GitHub's
**Security → Report a vulnerability** (private advisory) on this repo, or contact the
maintainer directly. A bypass report with a minimal reproducing diff is the single most
valuable contribution to a tool like this.

## Pull requests

- One logical change per PR; keep the diff short.
- Run all three selftests before pushing.
- `rules.yaml` and `*.md` are excluded from Vigil's self-scan because they carry attack
  patterns as data — keep attack literals out of comments in scanned source files.
- By opening a PR you agree to license your contribution under this repository's license.
