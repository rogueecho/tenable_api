"""
audit.py
--------
Audits a live Tenable Security Center instance against a known-good baseline.

Two audit passes are run:

  1. Configuration audit
     Compares live API values against typed expectations defined in a YAML
     baseline.  Three check types are supported:
       boolean – live value must equal expected (True or False)
       numeric – live value must satisfy min <= value <= max, or equal an
                 exact expected value
       string  – live value must exactly match expected

  2. Scope audit
     a. Uncovered scope  – every IP, CIDR, and hostname in the authorised
                           scope must overlap with at least one scan zone.
                           Hosts with no zone coverage will never be scanned.
     b. Out-of-scope scan – every IP/CIDR in every scan zone must be fully
                            contained within the authorised scope.  Anything
                            outside means the scanner may reach unauthorised
                            hosts.
     Hostnames cannot be evaluated against IP ranges without DNS resolution;
     they are flagged for manual verification.

Usage:
    python audit.py [--baseline audit_baseline.yaml] [--out audit_report.json]

Exit codes:
    0  – no issues found
    1  – one or more config failures or scope issues detected

Extending:
    Config checks  – add entries to the config_checks block in the baseline.
                     The key is "section.field" where section matches a key
                     in collect_config_report() (e.g. "config", "system_info").
    Scope entries  – add IPs, CIDRs, or hostnames to the scope block.
    New check types – add a branch in SecurityCenterAuditor._check_field() and
                      document the new spec keys in audit_baseline.yaml.
"""

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from tenable_sc import SecurityCenterClient

load_dotenv()


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """Outcome of a single configuration field check."""
    source:   str   # API section name (e.g. "config", "system_info")
    field:    str   # Dot-separated field path within that section
    status:   str   # "PASS" | "FAIL" | "SKIP"
    expected: Any   # Baseline expectation (value, range string, or spec dict)
    actual:   Any   # Value returned by the live API
    message:  str   # Human-readable detail; empty string on PASS


@dataclass
class ScopeIssue:
    """A gap or violation found during the scope audit."""
    category:  str  # "uncovered_scope" | "out_of_scope_scan"
    entry:     str  # IP, CIDR, or hostname that triggered the issue
    zone_name: str  # Relevant scan zone (empty if not zone-specific)
    message:   str  # Human-readable description


@dataclass
class AuditReport:
    """Aggregated results from a full audit run."""
    host:            str
    timestamp:       str
    config_results:  list[CheckResult]
    scope_issues:    list[ScopeIssue]

    @property
    def config_passed(self)  -> int: return sum(1 for r in self.config_results if r.status == "PASS")
    @property
    def config_failed(self)  -> int: return sum(1 for r in self.config_results if r.status == "FAIL")
    @property
    def config_skipped(self) -> int: return sum(1 for r in self.config_results if r.status == "SKIP")


# ── IP parsing helpers ────────────────────────────────────────────────────────

def parse_ip_entry(entry: str) -> list[ipaddress.IPv4Network]:
    """Parse a single IP entry string into one or more IPv4Network objects.

    Handles three formats used by both the baseline scope block and SC scan
    zone ipList fields:
      Single IP   "192.168.1.1"          → [IPv4Network("192.168.1.1/32")]
      CIDR        "192.168.0.0/16"       → [IPv4Network("192.168.0.0/16")]
      Dash range  "10.0.0.1-10.0.0.50"  → summarized list of covering CIDRs

    Returns an empty list for entries that cannot be parsed (e.g. hostnames).
    """
    entry = entry.strip()
    if not entry:
        return []

    # Dash range: "start-end" where both sides are valid IPv4 addresses.
    if "-" in entry:
        parts = entry.split("-", 1)
        try:
            start = ipaddress.IPv4Address(parts[0].strip())
            end   = ipaddress.IPv4Address(parts[1].strip())
            return list(ipaddress.summarize_address_range(start, end))
        except (ipaddress.AddressValueError, ValueError):
            pass  # fall through to single-address / CIDR attempt

    try:
        # strict=False accepts host bits set (e.g. "192.168.1.5/24" → /24 network)
        return [ipaddress.IPv4Network(entry, strict=False)]
    except ValueError:
        return []


def is_hostname(entry: str) -> bool:
    """Return True when entry looks like a DNS name rather than an IP or CIDR."""
    # If parse_ip_entry succeeds the entry is an IP-based value.
    return len(parse_ip_entry(entry)) == 0


def network_overlaps_scope(
    net: ipaddress.IPv4Network,
    scope: list[ipaddress.IPv4Network],
) -> bool:
    """Return True if net shares at least one address with any scope network."""
    return any(net.overlaps(s) for s in scope)


def network_contained_in_scope(
    net: ipaddress.IPv4Network,
    scope: list[ipaddress.IPv4Network],
) -> bool:
    """Return True if every address in net is covered by at least one scope network.

    Uses supernet_of: s.supernet_of(net) is True when s contains net entirely.
    """
    return any(s.supernet_of(net) or s == net for s in scope)


# ── Auditor ───────────────────────────────────────────────────────────────────

class SecurityCenterAuditor:
    """Runs configuration and scope audits against a live SC instance.

    Workflow:
        auditor = SecurityCenterAuditor(client, "audit_baseline.yaml")
        report  = auditor.run_full_audit()

    The baseline YAML structure is documented in audit_baseline.yaml.
    """

    def __init__(
        self,
        client: SecurityCenterClient,
        baseline_path: str | Path,
    ) -> None:
        """
        Args:
            client:        Authenticated SecurityCenterClient instance.
            baseline_path: Path to the YAML baseline file.
        """
        self._client    = client
        self._baseline  = self._load_baseline(Path(baseline_path))
        self._live_data: dict = {}

    # ── Baseline loading ──────────────────────────────────────────────────

    def _load_baseline(self, path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(f"Baseline file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"Baseline must be a YAML mapping, got {type(data)}")
        return data

    # ── Live data ─────────────────────────────────────────────────────────

    def _fetch_live_data(self) -> None:
        """Populate _live_data from the API.  Idempotent — only runs once."""
        if self._live_data:
            return
        print("Fetching live configuration from Security Center…")
        self._live_data = self._client.collect_config_report()

    # ── Type coercion ─────────────────────────────────────────────────────

    @staticmethod
    def _to_bool(value: Any) -> bool | None:
        """Coerce SC string booleans ("true"/"false"/0/1) to Python bool."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        if isinstance(value, str):
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False
        return None

    @staticmethod
    def _to_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    # ── Field resolution ──────────────────────────────────────────────────

    def _resolve_field(self, section: dict | Any, field_path: str) -> Any:
        """Walk a dot-separated path into a nested dict.

        e.g. field_path="license.status" on {"license": {"status": "Valid"}}
        returns "Valid".  Returns None if any step is missing.
        """
        node = section
        for part in field_path.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node

    # ── Individual check evaluators ───────────────────────────────────────

    def _check_boolean(
        self, source: str, field: str, actual: Any, spec: dict
    ) -> CheckResult:
        parsed   = self._to_bool(actual)
        expected = bool(spec["expected"])

        if parsed is None:
            return CheckResult(source, field, "SKIP", expected, actual,
                               f"Cannot parse '{actual}' as boolean")

        ok = (parsed == expected)
        return CheckResult(source, field,
                           "PASS" if ok else "FAIL",
                           expected, parsed,
                           "" if ok else f"Expected {expected}, got {parsed}")

    def _check_numeric(
        self, source: str, field: str, actual: Any, spec: dict
    ) -> CheckResult:
        parsed = self._to_float(actual)

        if parsed is None:
            return CheckResult(source, field, "SKIP", spec, actual,
                               f"Cannot parse '{actual}' as a number")

        if "expected" in spec:
            # Exact match
            expected = float(spec["expected"])
            ok = (parsed == expected)
            return CheckResult(source, field,
                               "PASS" if ok else "FAIL",
                               expected, parsed,
                               "" if ok else f"Expected {expected}, got {parsed}")

        # Range check
        lo = float(spec.get("min", "-inf"))
        hi = float(spec.get("max",  "inf"))
        ok = (lo <= parsed <= hi)
        range_str = f"{lo}–{hi}"
        return CheckResult(source, field,
                           "PASS" if ok else "FAIL",
                           range_str, parsed,
                           "" if ok else f"{parsed} is outside [{range_str}]")

    def _check_string(
        self, source: str, field: str, actual: Any, spec: dict
    ) -> CheckResult:
        expected = str(spec["expected"])
        actual_s = str(actual) if actual is not None else ""
        ok = (actual_s == expected)
        return CheckResult(source, field,
                           "PASS" if ok else "FAIL",
                           expected, actual_s,
                           "" if ok else f"Expected '{expected}', got '{actual_s}'")

    # ── Per-entry dispatch ────────────────────────────────────────────────

    def _check_field(self, source: str, field: str, spec: dict) -> CheckResult:
        """Evaluate one baseline entry against the live data."""
        section = self._live_data.get(source, {})

        if isinstance(section, dict) and "error" in section:
            return CheckResult(source, field, "SKIP", spec, None,
                               f"Section '{source}' failed to load: {section['error']}")

        actual = self._resolve_field(section, field)

        if actual is None:
            return CheckResult(source, field, "SKIP", spec, None,
                               f"Field '{field}' not present in '{source}' response")

        check_type = spec.get("type", "string").lower()

        if check_type == "boolean":
            return self._check_boolean(source, field, actual, spec)
        elif check_type == "numeric":
            return self._check_numeric(source, field, actual, spec)
        else:
            return self._check_string(source, field, actual, spec)

    # ── Config audit ──────────────────────────────────────────────────────

    def run_config_audit(self) -> list[CheckResult]:
        """Evaluate every entry in the baseline config_checks block.

        Baseline key format: "section.field"
          section – a top-level key in collect_config_report() output
                    (e.g. "config", "system_info", "status")
          field   – a dot-separated path within that section
                    (e.g. "sessionTimeout", "license.status")

        Returns a list of CheckResult objects in baseline definition order.
        """
        self._fetch_live_data()

        checks  = self._baseline.get("config_checks", {})
        results = []

        for key, spec in checks.items():
            # Split "section.field" — everything after the first dot is the field path
            # so nested fields like "system_info.license.status" are supported.
            parts  = key.split(".", 1)
            source = parts[0]
            field  = parts[1] if len(parts) > 1 else key
            results.append(self._check_field(source, field, spec))

        return results

    # ── Scope audit helpers ───────────────────────────────────────────────

    def _extract_zones(self) -> list[dict]:
        """Return the raw zone list from live data, handling usable/manageable wrapping."""
        raw = self._live_data.get("scan_zones", [])
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            if "error" in raw:
                raise RuntimeError(f"Could not load scan zones: {raw['error']}")
            return raw.get("usable") or raw.get("manageable") or []
        return []

    def _parse_zone_networks(
        self, zones: list[dict]
    ) -> dict[str, list[ipaddress.IPv4Network]]:
        """Build a map of zone_name → [IPv4Network, ...] from the zone ipList strings."""
        result: dict[str, list[ipaddress.IPv4Network]] = {}
        for zone in zones:
            name     = zone.get("name") or f"zone-{zone.get('id', '?')}"
            ip_list  = zone.get("ipList", "")
            networks = []
            for entry in ip_list.split(","):
                networks.extend(parse_ip_entry(entry.strip()))
            result[name] = networks
        return result

    def _build_scope_networks(self) -> tuple[list[ipaddress.IPv4Network], list[str]]:
        """Parse the baseline scope block into networks and unresolvable hostnames.

        Returns:
            (scope_networks, hostnames) – hostnames cannot be IP-compared without DNS.
        """
        scope_cfg  = self._baseline.get("scope", {})
        networks:  list[ipaddress.IPv4Network] = []
        hostnames: list[str] = []

        for cidr in scope_cfg.get("cidrs", []):
            networks.extend(parse_ip_entry(cidr))

        for entry in scope_cfg.get("ips", []):
            if is_hostname(entry):
                hostnames.append(entry)
            else:
                networks.extend(parse_ip_entry(entry))

        for h in scope_cfg.get("hostnames", []):
            hostnames.append(h)

        return networks, hostnames

    # ── Scope audit ───────────────────────────────────────────────────────

    def run_scope_audit(self) -> list[ScopeIssue]:
        """Check for scan blind spots and out-of-scope scanning.

        Pass 1 – Uncovered scope
            For each IP/CIDR in the authorised scope, verify it overlaps with
            at least one scan zone.  If not, those hosts will never be scanned.

        Pass 2 – Out-of-scope scanning
            For each IP/CIDR in each scan zone, verify it is fully contained
            within the authorised scope.  If not, the scanner may reach hosts
            that are outside the approved boundary.

        Hostnames are flagged for manual review because IP-range containment
        checks require a resolved address.

        Returns:
            List of ScopeIssue objects.  An empty list means all clear.
        """
        self._fetch_live_data()

        issues: list[ScopeIssue] = []

        try:
            zones = self._extract_zones()
        except RuntimeError as exc:
            issues.append(ScopeIssue("uncovered_scope", "(all)", "",
                                     str(exc)))
            return issues

        zone_networks  = self._parse_zone_networks(zones)
        all_zone_nets  = [n for nets in zone_networks.values() for n in nets]
        scope_nets, hostnames = self._build_scope_networks()

        scope_cfg = self._baseline.get("scope", {})

        # ── Pass 1: uncovered scope ───────────────────────────────────────

        for cidr in scope_cfg.get("cidrs", []):
            nets = parse_ip_entry(cidr)
            if nets and not network_overlaps_scope(nets[0], all_zone_nets):
                issues.append(ScopeIssue(
                    "uncovered_scope", cidr, "",
                    f"{cidr} has no overlap with any scan zone — "
                    f"hosts in this range will never be scanned",
                ))

        for entry in scope_cfg.get("ips", []):
            if is_hostname(entry):
                continue  # handled in hostname block below
            nets = parse_ip_entry(entry)
            if nets and not network_overlaps_scope(nets[0], all_zone_nets):
                issues.append(ScopeIssue(
                    "uncovered_scope", entry, "",
                    f"{entry} is not covered by any scan zone",
                ))

        for hostname in hostnames:
            # Cannot resolve without DNS — flag for manual verification.
            issues.append(ScopeIssue(
                "uncovered_scope", hostname, "",
                f"Hostname '{hostname}' requires DNS resolution to verify "
                f"scan zone coverage — check manually",
            ))

        # ── Pass 2: out-of-scope scanning ─────────────────────────────────

        for zone_name, nets in zone_networks.items():
            for net in nets:
                if not network_contained_in_scope(net, scope_nets):
                    issues.append(ScopeIssue(
                        "out_of_scope_scan", str(net), zone_name,
                        f"Scan zone '{zone_name}' includes {net} which is not "
                        f"fully contained within the authorised scope",
                    ))

        return issues

    # ── Full audit ────────────────────────────────────────────────────────

    def run_full_audit(self) -> AuditReport:
        """Run both audit passes and return a combined AuditReport."""
        config_results = self.run_config_audit()
        scope_issues   = self.run_scope_audit()

        return AuditReport(
            host=os.getenv("SC_HOST", "unknown"),
            timestamp=datetime.now(timezone.utc).isoformat(),
            config_results=config_results,
            scope_issues=scope_issues,
        )


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_report(report: AuditReport) -> None:
    """Write a human-readable audit summary to stdout."""
    sep  = "=" * 62
    line = "-" * 62

    print(f"\n{sep}")
    print(f"  Security Center Audit Report")
    print(f"  Host      : {report.host}")
    print(f"  Timestamp : {report.timestamp}")
    print(f"{sep}\n")

    # ── Config results ────────────────────────────────────────────────────
    print("CONFIG CHECKS")
    print(line)
    for r in report.config_results:
        label = f"{r.source}.{r.field}"
        if r.status == "PASS":
            print(f"  [PASS]  {label}")
        elif r.status == "FAIL":
            print(f"  [FAIL]  {label}")
            print(f"            expected : {r.expected}")
            print(f"            actual   : {r.actual}")
            if r.message:
                print(f"            detail   : {r.message}")
        else:
            print(f"  [SKIP]  {label}")
            if r.message:
                print(f"            reason   : {r.message}")

    print(
        f"\n  Result: {report.config_passed} passed  |  "
        f"{report.config_failed} failed  |  "
        f"{report.config_skipped} skipped\n"
    )

    # ── Scope results ─────────────────────────────────────────────────────
    print("SCOPE CHECKS")
    print(line)

    uncovered    = [i for i in report.scope_issues if i.category == "uncovered_scope"]
    out_of_scope = [i for i in report.scope_issues if i.category == "out_of_scope_scan"]

    if not uncovered and not out_of_scope:
        print("  [PASS]  No scope issues found\n")
    else:
        if uncovered:
            print(f"  Uncovered scope entries  ({len(uncovered)} issue(s)):")
            for issue in uncovered:
                print(f"    [FAIL]  {issue.entry}")
                print(f"              {issue.message}")

        if out_of_scope:
            print(f"\n  Out-of-scope scan entries  ({len(out_of_scope)} issue(s)):")
            for issue in out_of_scope:
                print(f"    [FAIL]  [{issue.zone_name}]  {issue.entry}")
                print(f"              {issue.message}")
        print()

    # ── Summary ───────────────────────────────────────────────────────────
    total_issues = report.config_failed + len(report.scope_issues)
    print(sep)
    if total_issues == 0:
        print("  RESULT: PASS — no issues found")
    else:
        print(f"  RESULT: FAIL — {total_issues} issue(s) require attention")
    print(sep)


def write_report(report: AuditReport, path: str | Path) -> None:
    """Serialize the full audit report to a JSON file."""
    out = {
        "host":      report.host,
        "timestamp": report.timestamp,
        "config_summary": {
            "passed":  report.config_passed,
            "failed":  report.config_failed,
            "skipped": report.config_skipped,
        },
        "config_results": [asdict(r) for r in report.config_results],
        "scope_summary": {
            "uncovered_scope":    sum(1 for i in report.scope_issues if i.category == "uncovered_scope"),
            "out_of_scope_scans": sum(1 for i in report.scope_issues if i.category == "out_of_scope_scan"),
        },
        "scope_issues": [asdict(i) for i in report.scope_issues],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit a Tenable Security Center instance against a known-good baseline."
    )
    parser.add_argument(
        "--baseline", default="audit_baseline.yaml",
        help="Path to the baseline YAML file  (default: audit_baseline.yaml)",
    )
    parser.add_argument(
        "--out", default="audit_report.json",
        help="Path for the JSON output report  (default: audit_report.json)",
    )
    args = parser.parse_args()

    host       = os.getenv("SC_HOST", "")
    access_key = os.getenv("SC_ACCESS_KEY", "")
    secret_key = os.getenv("SC_SECRET_KEY", "")
    verify_ssl = os.getenv("SC_VERIFY_SSL", "true").lower() != "false"

    if not all([host, access_key, secret_key]):
        sys.exit(
            "Error: SC_HOST, SC_ACCESS_KEY, and SC_SECRET_KEY must be set.\n"
            "Copy .env.example to .env and fill in your credentials."
        )

    client  = SecurityCenterClient(
        host=host, access_key=access_key,
        secret_key=secret_key, verify_ssl=verify_ssl,
    )
    auditor = SecurityCenterAuditor(client, args.baseline)
    report  = auditor.run_full_audit()

    print_report(report)
    write_report(report, args.out)
    print(f"\nFull report written to {args.out}")

    sys.exit(1 if (report.config_failed or report.scope_issues) else 0)


if __name__ == "__main__":
    main()
