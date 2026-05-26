# Tenable Security Center Audit Tools

A Python toolkit for querying a Tenable Security Center (SC) instance via its REST API and auditing its configuration against a known-good baseline.

## Contents

| File | Purpose |
|---|---|
| `tenable_sc.py` | SC API client — authentication, pagination, data collection |
| `audit.py` | Auditor — compares live config to a YAML baseline, checks scan zone scope |
| `xml_to_baseline.py` | Converter — turns an XML SC config export into a baseline YAML |
| `audit_baseline.yaml` | Example baseline (edit before use) |
| `sample_config.xml` | Example XML input for `xml_to_baseline.py` |

---

## Requirements

- Python 3.10+
- Tenable Security Center 5.13+ (API key authentication)

---

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

**.env** (never commit this file):

```ini
SC_HOST=securitycenter.example.com
SC_ACCESS_KEY=your-access-key-here
SC_SECRET_KEY=your-secret-key-here
SC_VERIFY_SSL=false   # set to true in production
```

API keys are generated in SC under **System > Users > [user] > API Keys**.

---

## Workflow overview

```
XML export  ──►  xml_to_baseline.py  ──►  baseline.yaml
                                               │
                                               ▼
                               audit.py  ──►  report (stdout + JSON)
```

### Step 1 — Build a baseline from an XML export

Export the SC configuration as XML (or use `sample_config.xml` to test), then convert it:

```bash
python xml_to_baseline.py sample_config.xml
# Output: sample_config_baseline.yaml
```

Specify an output path or description:

```bash
python xml_to_baseline.py export.xml --out prod_baseline.yaml --description "Q3 2026 baseline"
```

Exclude fields you do not want to check:

```bash
python xml_to_baseline.py export.xml --exclude smtpHost,smtpFromAddress,ldapHost
```

The converter writes exact-match checks for every field it finds. **Numeric fields default to exact match.** To express a range, open the YAML and replace `expected` with `min`, `max`, or both:

```yaml
# Exact match (generated default)
config.sessionTimeout:
  type: numeric
  expected: 30

# Range check (manually edited)
config.sessionTimeout:
  type: numeric
  min: 15
  max: 60

# One-sided — value must not exceed 72 hours (259200 seconds)
status.scanCompletionTime:
  type: numeric
  max: 259200
```

### Step 2 — Add the scope block

The converter does not generate a `scope` block; add it manually. The scope defines the authorised scanning boundary used by the scope audit:

```yaml
scope:
  cidrs:
    - "192.168.0.0/16"     # Corporate LAN — must be covered by a scan zone
    - "10.10.0.0/24"       # DMZ segment
  ips:
    - "192.168.1.50"       # Management host that must always be scanned
  hostnames:
    - "server01.corp.example.com"   # Flagged for manual DNS verification
```

### Step 3 — Run the audit

```bash
python audit.py
# Uses audit_baseline.yaml and writes audit_report.json by default
```

Custom paths:

```bash
python audit.py --baseline prod_baseline.yaml --out reports/2026-Q3.json
```

The script prints a summary to stdout and exits with:
- **0** — all checks passed, no scope issues
- **1** — one or more failures or scope issues found

---

## Baseline YAML reference

```yaml
version: "1.0"
description: "Production SC security baseline"

config_checks:

  # String check — exact case-sensitive match
  system_info.licenseStatus:
    type: string
    expected: "Valid"

  # Boolean check
  config.ldapEnabled:
    type: boolean
    expected: true

  # Numeric — exact match
  config.smtpPort:
    type: numeric
    expected: 25

  # Numeric — range (both bounds inclusive; omit either for one-sided)
  config.sessionTimeout:
    type: numeric
    min: 15
    max: 60

scope:
  cidrs:
    - "192.168.0.0/16"
  ips:
    - "10.10.0.100"
  hostnames:
    - "server01.corp.example.com"
```

**Baseline key format:** `"section.field"` where `section` matches a key returned by `collect_config_report()`:

| Section key | SC API source |
|---|---|
| `config` | `/rest/config` |
| `system_info` | `/rest/system` |
| `status` | `/rest/status` |
| `current_user` | `/rest/currentUser` |
| `ip_info` | `/rest/ipInfo` |
| `scanners` | `/rest/scanner` |
| `repositories` | `/rest/repository` |
| `scan_zones` | `/rest/zone` |
| `organizations` | `/rest/organization` |

---

## XML input format

Two styles are accepted and may be mixed in the same file.

**Nested sections** (preferred):

```xml
<SecurityCenterConfig host="sc.example.com" exported="2026-05-26T00:00:00Z">
  <config>
    <sessionTimeout>30</sessionTimeout>
    <ldapEnabled>true</ldapEnabled>
  </config>
  <system_info>
    <licenseStatus>Valid</licenseStatus>
  </system_info>
</SecurityCenterConfig>
```

**Flat `<Setting>` attributes:**

```xml
<Settings>
  <Setting name="sessionTimeout" value="30"    section="config"/>
  <Setting name="ldapEnabled"    value="true"  section="config"/>
  <Setting name="licenseStatus"  value="Valid" section="system_info"/>
</Settings>
```

The `section` attribute defaults to `"config"` when omitted. If the same key appears in both styles, the nested-section value takes precedence.

---

## Example audit output

```
==============================================================
  Security Center Audit Report
  Host      : securitycenter.example.com
  Timestamp : 2026-05-26T14:32:01+00:00
==============================================================

CONFIG CHECKS
--------------------------------------------------------------
  [PASS]  system_info.licenseStatus
  [PASS]  config.smtpEncryption
  [PASS]  config.ldapEnabled
  [FAIL]  config.sessionTimeout
            expected : 15.0-60.0
            actual   : 120.0
            detail   : 120.0 is outside [15.0-60.0]
  [PASS]  status.feedStatus

  Result: 4 passed  |  1 failed  |  0 skipped

SCOPE CHECKS
--------------------------------------------------------------
  Uncovered scope entries  (1 issue(s)):
    [FAIL]  172.16.50.0/24
              172.16.50.0/24 has no overlap with any scan zone — hosts in this range will never be scanned

==============================================================
  RESULT: FAIL — 2 issue(s) require attention
==============================================================

Full report written to audit_report.json
```

---

## Extending

**Add a new config check** — add an entry to `config_checks` in the baseline YAML. No code changes needed.

**Add a new API section** — implement a method on `SecurityCenterClient` in `tenable_sc.py` and register it in `collect_config_report()`. The new section key becomes available immediately as a baseline prefix.

**Add a new check type** — add a branch in `SecurityCenterAuditor._check_field()` in `audit.py` and define the new spec keys in the baseline.

---

## Security notes

- Credentials are read exclusively from `.env` which is listed in `.gitignore`. Never commit real credentials.
- Set `SC_VERIFY_SSL=true` in production environments. The `false` default is for lab/test use only.
- API keys should be scoped to a read-only SC role where possible. `audit.py` and `tenable_sc.py` perform only GET requests (no writes) except for the file upload helpers which are unused by the audit workflow.
