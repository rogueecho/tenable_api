# Tenable Security Center Scan Policy & Scope Auditor

A small Python toolkit that pulls scan policy and asset data out of a
Tenable Security Center (SC) instance via [pyTenable](https://pytenable.readthedocs.io/)
and audits it two ways:

- **Policy config** against a hand-authored "golden copy" baseline, using
  [DeepDiff](https://zepworks.com/deepdiff/).
- **Asset scope coverage** against an authorised scope extracted from
  arbitrary scoping documents, using IP/CIDR containment checks.

## What this actually does

Security Center has three distinct, easily-confused object types:

| Object | Endpoint | What it is |
|---|---|---|
| **Scan policy** | `/rest/policy` | A reusable template of scan settings — preferences, plugin family selection, audit files. No targets, no schedule. |
| Scan | `/rest/scan` | A configured scan: a policy plus targets, a schedule, a repository, a zone. |
| Scan result | `/rest/scanResult` | One executed run of a scan: status, start/finish time, IP/check counts. |

This toolkit works exclusively with **scan policies** (the first row). It
does not touch scan definitions or scan results.

## Contents

| File | Purpose |
|---|---|
| [tenable_sc.py](tenable_sc.py) | Pulls every scan policy's full configuration and every asset list's IPs from SC, writes both to JSON |
| [scope_extractor.py](scope_extractor.py) | Extracts IPs/CIDRs/hostnames from arbitrary scoping documents (text, CSV, Word, PDF, routing tables, ...) |
| [audit.py](audit.py) | Two subcommands: `policy` diffs a live scan policy against a golden-copy XML baseline; `scope` compares live asset IPs against an authorised scope |
| [golden_scan_policy.xml](golden_scan_policy.xml) | Example golden-copy policy baseline, for use with `audit.py policy` |
| [sample_scan_policy.json](sample_scan_policy.json) | Example live policy JSON, for testing `audit.py policy` without a live SC instance |

## Requirements

- Python 3.10+
- Tenable Security Center 5.13+ (API key authentication)
- An API key pair with permission to read scan policies

## Installation

```bash
# 1. Clone the repo
git clone <repo-url>
cd tenable_api

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # PowerShell
# source .venv/bin/activate        # bash/zsh

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure credentials
copy .env.example .env
# Edit .env and fill in SC_HOST, SC_ACCESS_KEY, SC_SECRET_KEY
```

**requirements.txt:**

```
pytenable>=26.6
python-dotenv>=1.0
deepdiff>=9.1
colorama>=0.4
defusedxml>=0.7
pyyaml>=6.0
```

**.env** (copied from `.env.example`; never commit this file):

```ini
SC_HOST=securitycenter.example.com
SC_ACCESS_KEY=your-access-key-here
SC_SECRET_KEY=your-secret-key-here
SC_VERIFY_SSL=false   # set to true in production
```

API keys are generated in SC under **Users > Your Profile > API Keys >
Generate**.

## Workflow

```
tenable_sc.py  ──►  scan_policies.json  ──►  audit.py policy  ──►  stdout report + audit_report.json
                       │  ▲                        ▲
                       │  └── golden_scan_policy.xml (hand-authored once)
                       │
                       └─────────────────────────►  audit.py scope  ──►  stdout report + scope_audit_report.json
                                                          ▲
scoping documents ──►  scope_extractor.py  ──►  scope.yaml
```

### Step 1 — Pull live scan policy configurations

```bash
python tenable_sc.py
```

This authenticates to SC and pulls two things:

- **Scan policies** — calls `GET /policy` to enumerate every configured
  scan policy, then calls `GET /policy/{id}` for each one to get its full
  configuration (preferences, audit files, and — for Advanced Scan/Audit
  templates — plugin family selections). The list endpoint alone only
  returns summary fields (name, description, status, ...), so this extra
  per-policy call is required to get anything worth auditing.
- **Assets** — calls `GET /asset` to enumerate every configured asset
  list, then calls `GET /asset/{id}` for each one requesting the
  `viewableIPs` field (omitted by default) to get that list's actual
  resolved IP membership. Every repository's IPs, across every asset
  list, are merged into one deduplicated, sorted set.

Output:

```
Collecting scan policy configurations from securitycenter.example.com ...
  [ok]  policy 5 (PCI Quarterly)
  [ok]  policy 7 (CIS Hardening Baseline)
  [err] policy 9 (Legacy Audit): 403 Forbidden ...
Collecting asset list IPs from securitycenter.example.com ...
  [ok]  asset list 1 (Web Servers): 42 IP(s)
  [ok]  asset list 2 (DB Servers): 11 IP(s)
  2 scan policy configuration(s) found
  50 deduplicated asset IP(s) found

Report written to scan_policies.json
```

`scan_policies.json` is a single JSON object:

```json
{
  "scan_policies": [ /* one entry per policy, each its full configuration */ ],
  "assets":        [ /* deduplicated, sorted IPs across every asset list */ ]
}
```

If a given policy's details call (or asset list's IP lookup) fails (e.g. a
permissions error), that one entry is skipped/recorded with an error
instead of aborting the whole run — everything else already collected is
still written out.

### Step 2 — Author a golden-copy baseline (once, by hand)

There is no converter that generates this for you — write an XML file
describing what a policy's configuration *should* look like. See
[golden_scan_policy.xml](golden_scan_policy.xml) for a complete example.

Rules `audit.py` applies when parsing this file:

- Nested elements become nested dict keys.
- Repeated sibling elements with the **same tag** collapse into a list —
  with no wrapper element, e.g.:
  ```xml
  <auditFiles><id>10</id><name>CIS_Windows_2019_Level1</name></auditFiles>
  <auditFiles><id>11</id><name>CIS_RHEL8_Level1</name></auditFiles>
  ```
  becomes `"auditFiles": [{"id": "10", ...}, {"id": "11", ...}]`, matching
  the shape SC's API actually returns.
- Leaf text is compared as a **plain string** by default — `<status>0</status>`
  becomes `"0"`, not `0` — because the SC REST API returns nearly every
  field as a string, even numeric and boolean ones. Coercing types here
  would manufacture false discrepancies against that live data. Pass
  `--infer-types` to opt into bool/int/float coercion if your use case
  needs it.
- Empty elements (`<context></context>`) become `""`, not `null` — SC
  returns unset string fields as empty strings, not JSON `null`.
- Element attributes are ignored; only nested elements and text are read.

### Step 3 — Audit a live policy against the baseline

```bash
# Compare against a single saved policy JSON file
python audit.py policy --golden golden_scan_policy.xml --current scan_policy.json

# Pick one entry out of the "scan_policies" list in the blob tenable_sc.py just wrote
python audit.py policy --golden golden_scan_policy.xml --current scan_policies.json --index 0

# Pipe straight from tenable_sc.py's output without an intermediate file
type scan_policies.json | python audit.py policy --golden golden_scan_policy.xml --index 0
```

Try it now with the bundled samples (no live SC instance needed):

```bash
python audit.py policy --golden golden_scan_policy.xml --current sample_scan_policy.json --index 0
```

#### Output

stdout gets a color-coded, `+`/`-` marked report, from the point of view of
the live (non-golden) copy:

- `+` (green) — present in the live config but not the golden baseline (an addition)
- `-` (red) — present in the golden baseline but not the live config (a removal)
- A changed value prints both lines together, so a drifted field reads like
  a tiny unified diff

```
================================================================
  Scan Policy Configuration Audit
  Golden (baseline) : golden_scan_policy.xml
  Current (live)    : sample_scan_policy.json
================================================================

  + root['id']: '7'
  - root['auditFiles'][1]: {'id': '11', 'name': 'CIS_RHEL8_Level1'}
  - root['preferences']['thorough_tests']: 'no'
  + root['preferences']['thorough_tests']: 'yes'
  - root['families'][1]['state']: 'disabled'
  + root['families'][1]['state']: 'enabled'

================================================================
  RESULT: FAIL - 4 discrepancy(ies) found
================================================================

Full report written to audit_report.json
```

The same discrepancies are also written as structured JSON (via
`DeepDiff.to_json()`, no color codes) to the path given by `--out` (default
`audit_report.json`) for programmatic consumption.

Exit codes: `0` no discrepancies, `1` discrepancies found (or a bad input —
see stderr for the message).

#### `policy` flags

| Flag | Effect |
|---|---|
| `--index N` / `-i N` | Select policy N when `--current` (or stdin) is a JSON array |
| `--out PATH` / `-o` | Where to write the structured JSON diff report (default `audit_report.json`) |
| `--exclude-path PATH` / `-e` | Exclude a DeepDiff path from comparison, e.g. `--exclude-path "root['modifiedTime']"`. Repeatable. |
| `--strict-order` | Treat list element order as significant (default: ignored) |
| `--infer-types` | Coerce golden XML leaf text to bool/int/float instead of comparing as strings |
| `--no-color` | Disable ANSI color in the stdout report |

### Step 4 — Audit asset scope coverage

First, turn a scoping document (an SOW, an asset list, a network export —
see [scope_extractor.py](scope_extractor.py)'s own docs for supported
formats, including Cisco/ASA/Palo Alto/Juniper routing table output) into
a structured scope file:

```bash
python scope_extractor.py SOW.docx network_export.txt --out scope.yaml
```

Then compare it against what Security Center's asset lists actually
resolve to:

```bash
python audit.py scope --golden scope.yaml --current scan_policies.json
```

`--golden` here is scope_extractor.py's output (the authorised boundary);
`--current` is tenable_sc.py's output (only its `"assets"` key is used —
`"scan_policies"` is ignored for this subcommand). Comparison is
CIDR-aware: a scope entry like `10.0.0.0/24` is satisfied by any live
asset IP inside that range, not just an exact string match.

Two kinds of finding, printed with the same `+`/`-` convention as
`policy` (scope plays the "golden" role, live assets play "current"):

- `-` (red) **uncovered scope** — authorised but no live asset matches it; a potential blind spot.
- `+` (green) **out-of-scope asset** — being scanned but not within any authorised range.

Scope hostnames can't be checked against IP-only live data without DNS
resolution, so they're listed separately for manual verification rather
than silently passed or failed. Findings are also written as JSON to
`--out` (default `scope_audit_report.json`). Exit codes match `policy`:
`0` clean, `1` findings (or bad input).

## Extending

**Pull additional SC objects** — pyTenable exposes one namespace per SC API
object on the `TenableSC` instance (`sc.policies`, `sc.scans`,
`sc.scan_instances`, `sc.asset_lists`, `sc.repositories`, `sc.scan_zones`,
`sc.organizations`, `sc.credentials`, ...). Add a method to
`SecurityCenterClient` in [tenable_sc.py](tenable_sc.py) that calls the
relevant namespace and shapes the result the way callers need —
pagination, auth, and retries are already handled by pyTenable. To add it
to the combined blob `main()` writes, collect it the same way
`scan_policies`/`assets` are and add a key to the `output` dict there.

**Adjust the policy comparison** — `compare_configs()` in [audit.py](audit.py)
threads `ignore_order`/`exclude_paths` through to `DeepDiff`; other DeepDiff
options (`significant_digits`, `exclude_regex_paths`, etc.) can be added
the same way.

**Adjust the scope comparison** — `compare_scope()` in [audit.py](audit.py)
does the CIDR-containment checks; add a new `ScopeIssue` category there
(and a heading in `print_scope_report()`) for new kinds of finding.

## Security notes

- Credentials are read exclusively from `.env`, which is listed in
  `.gitignore`. Never commit real credentials.
- Set `SC_VERIFY_SSL=true` in production environments. The `false` default
  in `.env.example` is for lab/test use only.
- `tenable_sc.py` and `audit.py` only perform read (`GET`) requests
  against the SC API — an API key scoped to a read-only role is
  sufficient. `scope_extractor.py` makes no network calls at all; it only
  reads local files.
