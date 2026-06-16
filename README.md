# tenable_api

Pulls scan policy and asset data from a Tenable Security Center (SC)
instance and audits it two ways: scan policy config vs. a hand-written
golden-copy baseline, and live asset coverage vs. an authorised scope
extracted from arbitrary documents.

## Install

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # PowerShell
pip install -r requirements.txt
copy .env.example .env
```

`.env`:

```ini
SC_HOST=securitycenter.example.com
SC_ACCESS_KEY=your-access-key-here
SC_SECRET_KEY=your-secret-key-here
SC_VERIFY_SSL=true
```

`requirements.txt`: `pytenable`, `python-dotenv`, `deepdiff`, `colorama`, `defusedxml`, `pyyaml`

---

## tenable_sc.py

Authenticates to SC via pyTenable and pulls every scan policy's full
configuration (preferences, audit files, plugin families) plus the
deduplicated IP membership of every asset list.

```bash
python tenable_sc.py
```

No arguments. Writes `scan_policies.json`:

```json
{
  "scan_policies": [ { "...full policy config..." } ],
  "assets":        [ "10.0.0.5", "192.168.1.50" ]
}
```

---

## scope_extractor.py

Extracts IPs, CIDRs, and hostnames from arbitrarily-formatted documents
(text, CSV, Word, PDF, routing table dumps from Cisco/ASA/Palo
Alto/Juniper, ...) into one structured scope file. Use this to turn a
scoping document into something `audit.py scope` can compare against.

```bash
scope_extractor.py [paths ...] [options]
```

| Flag | Default | Effect |
|---|---|---|
| `paths` | stdin | files/directories to scan |
| `--recursive`, `-r` | off | descend into subdirectories |
| `--out`, `-o` | `scope.yaml` | output path |
| `--format`, `-f {yaml,json}` | inferred from `--out` | output format |
| `--exclude-tld EXT` | (repeatable) | extra extension to exclude from hostname matches |
| `--no-ips` | off | skip IP extraction |
| `--no-cidrs` | off | skip CIDR extraction |
| `--no-hostnames` | off | skip hostname extraction |

```bash
python scope_extractor.py notes.txt SOW.docx
python scope_extractor.py ./scoping_docs --recursive --out scope.yaml
type notes.txt | python scope_extractor.py --out scope.json
python scope_extractor.py routers.txt --no-hostnames --exclude-tld rst
```

Output (`scope.yaml`):

```yaml
generated: '2026-06-16T15:54:17Z'
sources: [notes.txt]
cidrs: [10.0.0.0/24]
ips: [192.168.1.50]
hostnames: [server01.corp.example.com]
```

---

## audit.py policy

Diffs a live scan policy (JSON, from `tenable_sc.py`) against a
hand-written golden-copy XML baseline, using DeepDiff. `+` (green) means
present in the live config but not the baseline; `-` (red) means the
reverse.

```bash
audit.py policy --golden GOLDEN.xml [--current CURRENT.json] [options]
```

| Flag | Default | Effect |
|---|---|---|
| `--golden`, `-g` | *required* | golden-copy XML baseline |
| `--current`, `-c` | stdin | live policy JSON (single object, list, or `scan_policies.json` blob) |
| `--index`, `-i` | — | select entry when `--current` holds multiple policies |
| `--out`, `-o` | `audit_report.json` | JSON diff report path |
| `--exclude-path`, `-e PATH` | (repeatable) | DeepDiff path to ignore, e.g. `"root['modifiedTime']"` |
| `--strict-order` | off | treat list order as significant |
| `--infer-types` | off | coerce XML leaf text to bool/int/float |
| `--no-color` | off | disable ANSI color |

```bash
audit.py policy --golden golden_scan_policy.xml --current scan_policy.json
audit.py policy --golden golden_scan_policy.xml --current scan_policies.json --index 0
type scan_policies.json | audit.py policy --golden golden_scan_policy.xml --index 0
audit.py policy --golden golden_scan_policy.xml --current scan_policy.json --exclude-path "root['modifiedTime']"
```

Exit: `0` no diff, `1` diff found.

---

## audit.py scope

Compares live asset IPs (`tenable_sc.py`'s `"assets"` key) against an
authorised scope (`scope_extractor.py`'s output), using CIDR-aware
containment rather than literal string matching. Reports scope entries
with no matching live asset (a blind spot) and live assets outside the
authorised scope; scope hostnames are listed separately since they need
DNS resolution to verify.

```bash
audit.py scope --golden SCOPE.yaml [--current CURRENT.json] [options]
```

| Flag | Default | Effect |
|---|---|---|
| `--golden`, `-g` | *required* | scope_extractor.py output (YAML/JSON) |
| `--current`, `-c` | stdin | tenable_sc.py output (uses `"assets"` key) or bare IP array |
| `--out`, `-o` | `scope_audit_report.json` | JSON findings report path |
| `--no-color` | off | disable ANSI color |

```bash
audit.py scope --golden scope.yaml --current scan_policies.json
type scan_policies.json | audit.py scope --golden scope.yaml
```

Exit: `0` no findings, `1` findings found.

---

## Pipeline

```bash
python tenable_sc.py
python scope_extractor.py SOW.docx --out scope.yaml
python audit.py policy --golden golden_scan_policy.xml --current scan_policies.json --index 0
python audit.py scope --golden scope.yaml --current scan_policies.json
```
