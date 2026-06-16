"""
audit.py
--------
Two related but independent Security Center audits, selected with a
subcommand:

  policy  – diffs a live scan policy configuration (JSON) against a
            golden-copy baseline (XML) using DeepDiff.
  scope   – compares tenable_sc.py's live asset IPs (from Security
            Center's asset lists) against an authorised scope extracted
            from documents by scope_extractor.py, using CIDR-aware
            containment checks rather than literal string comparison.

=====================================================================
 policy
=====================================================================
A "scan policy" here means the object returned by GET /policy/{id} — a
reusable template of scan preferences, audit files, and plugin family
selections.  It is distinct from a "scan" (which adds targets/schedule/
repository on top of a policy) and a "scan result" (one executed run).  See
the docstring in tenable_sc.py for the full distinction.

Inputs
------
  --golden   – an XML file describing the known-good configuration of one
               scan policy.  Nested elements map to nested dict keys;
               repeated sibling elements with the same tag collapse into a
               list.  Leaf text is kept as a plain string by default (see
               --infer-types) because the SC REST API returns nearly every
               policy field — including numbers and booleans — as a string;
               coercing types here would manufacture spurious discrepancies
               against that live data.

  --current  – the live configuration of a single scan policy as JSON, i.e.
               one entry from the "scan_policies" list returned by
               tenable_sc.SecurityCenterClient.collect_scan_policy_configs().
               Read from a file or from stdin (pipe it straight out of
               tenable_sc.py).  Three input shapes are accepted: a single
               policy object, a bare list of them, or the combined blob
               tenable_sc.py's main() writes to scan_policies.json
               ({"scan_policies": [...], "assets": [...]}) — the "assets"
               key is ignored here.  If a list of policies is in play
               (either bare or unwrapped from the blob), --index selects
               which entry to audit.

Comparison
----------
DeepDiff(golden, current) is used so that "old"/t1 is always the golden
baseline and "new"/t2 is always the live config.  That makes the +/- output
read like a conventional diff from the point of view of the live (non-
golden) copy:
    +  present in current but not golden   (an addition vs. the baseline)
    -  present in golden but not current   (a removal vs. the baseline)
A changed value prints both lines so a single field's drift reads like a
tiny unified diff.

Usage:
    # Compare a golden XML file against a single live scan policy JSON file
    python audit.py policy --golden golden_scan_policy.xml --current scan_policy.json

    # Pipe straight from tenable_sc.py and pick one entry out of the array
    python tenable_sc.py
    python audit.py policy --golden golden_scan_policy.xml --current scan_policies.json --index 0
    type scan_policies.json | python audit.py policy --golden golden_scan_policy.xml --index 0

    # Ignore fields that are expected to change between runs
    python audit.py policy --golden golden_scan_policy.xml --current scan_policy.json ^
        --exclude-path "root['modifiedTime']"

Extending:
    New comparison knobs (significant_digits, exclude_regex_paths, etc.) can
    be threaded through compare_configs() — see the DeepDiff documentation
    for the full option set.

=====================================================================
 scope
=====================================================================
Compares what Security Center is actually scanning against what a
scoping document says is authorised, using IP/CIDR containment — not
DeepDiff, which only knows literal value equality and has no concept of
"this /24 covers that address".

Inputs
------
  --golden   – scope_extractor.py's output file (YAML or JSON, detected by
               extension): a mapping with "cidrs", "ips", and "hostnames"
               lists.  This is the authorised scope — the "known good"
               boundary, playing the same baseline role --golden plays for
               the policy subcommand.

  --current  – tenable_sc.py's output: either the full
               {"scan_policies": [...], "assets": [...]} blob (the
               "assets" key — a deduplicated list of every IP Security
               Center's asset lists resolve to — is used; "scan_policies"
               is ignored here), or a bare JSON array of IP strings.  Read
               from a file or from stdin.

Comparison
----------
Every scope CIDR/IP is converted to an ipaddress network (a bare IP
becomes a single-host /32 or /128); every live asset entry is parsed as an
address.  Two passes, mirroring the old pre-rewrite scope audit:

  uncovered scope     – a scope CIDR/IP with no live asset address inside
                         it: something authorised that doesn't appear to
                         be getting scanned (a blind spot).
  out-of-scope asset   – a live asset address not contained in any scope
                         CIDR/IP: something being scanned outside the
                         authorised boundary.

Scope hostnames can't be matched against IP-only live asset data without
DNS resolution, so each is flagged for manual verification rather than
silently skipped.  Unparseable entries on either side are skipped with a
warning rather than aborting the comparison.

Following the same +/- convention as the policy subcommand (scope is the
baseline/"golden", live assets are "current"):
    +  out-of-scope asset  (green) — present in current, not in golden
    -  uncovered scope     (red)   — present in golden, not in current

Usage:
    python tenable_sc.py
    python scope_extractor.py scoping_docs/ --recursive --out scope.yaml
    python audit.py scope --golden scope.yaml --current scan_policies.json

=====================================================================
Exit codes (both subcommands):
    0  – no discrepancies found
    1  – one or more discrepancies found
    (a malformed/missing input exits non-zero via sys.exit(<message>))
"""

import argparse
import ipaddress
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import colorama
import defusedxml.ElementTree as DET
import yaml
from deepdiff import DeepDiff

colorama.init()

# ── ANSI color helpers ────────────────────────────────────────────────────────

_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(text: str, color: str, enabled: bool) -> str:
    """Wrap text in an ANSI color code, or return it unchanged when disabled."""
    return f"{color}{text}{_RESET}" if enabled else text


# ── XML golden-copy parsing ───────────────────────────────────────────────────

def _infer_scalar(text: str) -> Any:
    """Best-effort coercion of an XML leaf string to bool/int/float.

    Only used when --infer-types is passed.  Off by default: the SC API
    returns almost all scan policy fields as strings (even numeric and
    boolean ones), so coercing "30" -> 30 here would create a false
    type_changes discrepancy against the live "30" string it's diffed
    against.
    """
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _xml_element_to_value(elem: ET.Element, infer_types: bool) -> Any:
    """Recursively convert one XML element into a dict/list/scalar.

    Rules:
      • No children            → leaf; text becomes a string (or a coerced
                                  scalar when infer_types is set).  Empty/
                                  whitespace-only text becomes "" (not None)
                                  because the SC API returns unset string
                                  fields as "" rather than JSON null — using
                                  None here would manufacture a spurious
                                  discrepancy against every such field.
      • Children present       → dict of {tag: value}.
      • Repeated sibling tags  → collapse into a list under that tag.
    Attributes are ignored; only element text and nested elements are read.
    """
    children = list(elem)

    if not children:
        text = (elem.text or "").strip()
        return _infer_scalar(text) if infer_types else text

    result: dict[str, Any] = {}
    for child in children:
        value = _xml_element_to_value(child, infer_types)
        if child.tag in result:
            existing = result[child.tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[child.tag] = [existing, value]
        else:
            result[child.tag] = value
    return result


def xml_to_dict(xml_path: str | Path, infer_types: bool = False) -> dict[str, Any]:
    """Parse a golden-copy XML file into a dict comparable to a live scan
    policy JSON object.

    The root element's own tag is discarded — only its children become
    top-level keys — so <ScanPolicy><name>...</name></ScanPolicy>
    produces {"name": ...} rather than {"ScanPolicy": {"name": ...}}.

    Parsing uses defusedxml rather than the stdlib xml.etree.ElementTree
    directly: stock ElementTree does not guard against entity-expansion
    ("billion laughs") or quadratic-blowup XML denial-of-service payloads.
    The golden file is meant to be hand-authored and trusted, but rejecting
    DTDs/entities outright costs nothing and removes the risk if a golden
    file is ever sourced from somewhere less trusted (e.g. fetched by CI).

    Raises:
        FileNotFoundError if xml_path does not exist.
        ET.ParseError on malformed XML.
        ValueError if the XML contains a DTD/entity/external reference
            (rejected by defusedxml), or if the root element has no
            children to convert.
    """
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        tree = DET.parse(path)
    except ET.ParseError as exc:
        raise ET.ParseError(f"Malformed XML in {path}: {exc}") from exc

    value = _xml_element_to_value(tree.getroot(), infer_types)
    if not isinstance(value, dict):
        raise ValueError(
            f"{path}: root element <{tree.getroot().tag}> has no child "
            f"elements to compare — nothing to diff"
        )
    return value


# ── Live JSON loading ─────────────────────────────────────────────────────────

def _load_json_file(path: str | Path) -> Any:
    """Load and parse a JSON file, raising a clear error on failure."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    with open(p, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in {p}: {exc}") from exc


def _select_scan_policy(data: Any, index: int | None) -> dict[str, Any]:
    """Normalise loaded JSON into a single scan policy dict.

    Accepts any of:
      - a single scan policy object
      - a list of them (as produced by
        tenable_sc.SecurityCenterClient.collect_scan_policy_configs())
      - the combined blob tenable_sc.py's main() writes to scan_policies.json:
        {"scan_policies": [...], "assets": [...]} — unwrapped to the
        "scan_policies" list before the rest of this function runs, so this
        dict is never mistaken for a single policy object itself.
    `index` selects which entry to use once a list is in hand.
    """
    if isinstance(data, dict) and "scan_policies" in data:
        data = data["scan_policies"]

    if isinstance(data, dict):
        return data

    if isinstance(data, list):
        if not data:
            raise ValueError("Input list is empty — no scan policy to audit")
        if index is None:
            if len(data) == 1:
                return data[0]
            raise ValueError(
                f"Input contains {len(data)} scan policies; pass --index to "
                f"select one (0-{len(data) - 1})"
            )
        try:
            return data[index]
        except IndexError:
            raise ValueError(
                f"--index {index} out of range (input has {len(data)} entries)"
            ) from None

    raise ValueError(f"Expected a JSON object or array, got {type(data).__name__}")


def load_current_config(path: str | None, index: int | None) -> dict[str, Any]:
    """Load the live scan policy config from a file path, or stdin if path is None."""
    if path is None:
        raw = sys.stdin.read()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON on stdin: {exc}") from exc
    else:
        data = _load_json_file(path)

    return _select_scan_policy(data, index)


# ── Comparison ─────────────────────────────────────────────────────────────────

def compare_configs(
    golden: dict[str, Any],
    current: dict[str, Any],
    ignore_order: bool = True,
    exclude_paths: list[str] | None = None,
) -> DeepDiff:
    """Diff a live scan policy config against the golden-copy baseline.

    golden is passed as DeepDiff's t1 ("old") and current as t2 ("new"), so
    old_value/new_value and added/removed semantics line up with the +/-
    convention used by print_diff(): "+" = only in current, "-" = only in
    golden.

    Args:
        golden:        Dict produced by xml_to_dict().
        current:       Dict produced by load_current_config().
        ignore_order:  Treat list order as insignificant (default True).
        exclude_paths: DeepDiff "exclude_paths" entries, e.g. "root['id']".

    Returns:
        A DeepDiff object — falsy (empty) when no differences were found.
    """
    return DeepDiff(
        golden,
        current,
        ignore_order=ignore_order,
        exclude_paths=exclude_paths or [],
        verbose_level=2,
    )


# ── Reporting ─────────────────────────────────────────────────────────────────

# Categories where every entry is something present only in the live config
# (an addition relative to the golden baseline) → printed with "+".
_ADDED_CATEGORIES = (
    "dictionary_item_added",
    "iterable_item_added",
    "set_item_added",
)

# Categories where every entry is something present only in the golden
# baseline (a removal relative to the live config) → printed with "-".
_REMOVED_CATEGORIES = (
    "dictionary_item_removed",
    "iterable_item_removed",
    "set_item_removed",
)

# Categories that carry both an old (golden) and new (current) value for the
# same path → printed as a "-" line followed by a "+" line.
_CHANGED_CATEGORIES = (
    "values_changed",
    "type_changes",
)


def print_diff(
    diff: DeepDiff,
    golden_label: str,
    current_label: str,
    use_color: bool = True,
) -> None:
    """Print a human-readable, +/- marked discrepancy report to stdout.

    Markers follow the live (non-golden) copy's point of view:
        +  present in current but not golden  (green)
        -  present in golden but not current  (red)
    A changed value prints both its "-" (golden) and "+" (current) lines
    together, so the report reads like a small unified diff.
    """
    sep = "=" * 64

    print(f"\n{sep}")
    print("  Scan Policy Configuration Audit")
    print(f"  Golden (baseline) : {golden_label}")
    print(f"  Current (live)    : {current_label}")
    print(f"{sep}\n")

    if not diff:
        print(_c("  RESULT: PASS - no discrepancies found", _GREEN, use_color))
        print(sep)
        return

    total = 0

    for category in _ADDED_CATEGORIES:
        for path, value in diff.get(category, {}).items():
            print(_c(f"  + {path}: {value!r}", _GREEN, use_color))
            total += 1

    for category in _REMOVED_CATEGORIES:
        for path, value in diff.get(category, {}).items():
            print(_c(f"  - {path}: {value!r}", _RED, use_color))
            total += 1

    for category in _CHANGED_CATEGORIES:
        for path, change in diff.get(category, {}).items():
            old = change.get("old_value")
            new = change.get("new_value")
            print(_c(f"  - {path}: {old!r}", _RED, use_color))
            print(_c(f"  + {path}: {new!r}", _GREEN, use_color))
            total += 1

    # Forward-compatible fallback: any DeepDiff category not explicitly
    # handled above (e.g. repetition_change) is still shown, neutrally
    # marked, rather than silently dropped or crashing this reporter.
    handled = _ADDED_CATEGORIES + _REMOVED_CATEGORIES + _CHANGED_CATEGORIES
    for category, items in diff.items():
        if category in handled:
            continue
        print(_c(f"  ~ {category}:", _YELLOW, use_color))
        for path, value in (items.items() if isinstance(items, dict) else enumerate(items)):
            print(f"      {path}: {value!r}")
            total += 1

    print(f"\n{sep}")
    print(_c(f"  RESULT: FAIL - {total} discrepancy(ies) found", _BOLD + _RED, use_color))
    print(sep)


def write_diff(diff: DeepDiff, path: str | Path) -> None:
    """Serialise the DeepDiff result to a JSON file (no ANSI color codes)."""
    Path(path).write_text(diff.to_json(indent=2), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
#  scope subcommand
# ═══════════════════════════════════════════════════════════════════════════

# ── Loading ───────────────────────────────────────────────────────────────────

def load_scope_file(path: str | Path) -> dict[str, Any]:
    """Load scope_extractor.py's output (YAML or JSON, by extension).

    Returns the raw mapping as written — callers read "cidrs"/"ips"/
    "hostnames" with .get(key) or [] so a missing key (e.g. a scope file
    produced with --no-hostnames) doesn't need special-casing here.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Malformed scope file {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"{p}: expected a mapping with cidrs/ips/hostnames keys, "
            f"got {type(data).__name__}"
        )
    return data


def load_live_assets(path: str | None) -> list[str]:
    """Load the live asset IP list from tenable_sc.py's output.

    Accepts either the full {"scan_policies": [...], "assets": [...]} blob
    main() writes ("scan_policies" is ignored here), or a bare JSON array
    of IP strings.  Reads from path, or from stdin if path is None.
    """
    if path is None:
        raw = sys.stdin.read()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON on stdin: {exc}") from exc
    else:
        data = _load_json_file(path)

    if isinstance(data, dict) and "assets" in data:
        data = data["assets"]

    if not isinstance(data, list):
        raise ValueError(
            f'Expected a JSON array of IPs, or a {{"assets": [...]}} object, '
            f"got {type(data).__name__}"
        )
    return data


# ── Comparison ─────────────────────────────────────────────────────────────────

@dataclass
class ScopeIssue:
    """A gap or violation found while comparing live assets to authorised scope."""
    category: str  # "uncovered_scope" | "out_of_scope_asset" | "unverified_hostname"
    entry:    str   # the scope CIDR/IP, live asset IP, or hostname that triggered this
    message:  str


def _parse_network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a bare IP or CIDR string into a network (a bare IP becomes a
    single-host /32 or /128).  Returns None rather than raising so callers
    can skip-and-warn on unparseable entries (e.g. a hostname in "ips")."""
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def compare_scope(live_assets: list[str], scope: dict[str, Any]) -> list[ScopeIssue]:
    """Compare live scanned asset IPs against an authorised scope.

    Pass 1 -- uncovered scope: every CIDR/IP in the authorised scope must
        be matched by at least one live asset address, or it's a blind
        spot (something authorised that doesn't appear to be scanned).
    Pass 2 -- out-of-scope assets: every live asset address must fall
        within at least one authorised scope CIDR/IP, or it's scanning
        something outside the approved boundary.
    Scope hostnames cannot be matched against IP-only live asset data
    without DNS resolution, so each is flagged for manual verification.
    Entries on either side that don't parse as a valid IP/CIDR are skipped
    with a warning rather than aborting the whole comparison.

    Args:
        live_assets: IP strings, e.g. from load_live_assets().
        scope:       Mapping with "cidrs"/"ips"/"hostnames" lists, e.g.
                     from load_scope_file().

    Returns:
        List of ScopeIssue — empty means full agreement.
    """
    scope_networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for entry in [*(scope.get("cidrs") or []), *(scope.get("ips") or [])]:
        net = _parse_network(entry)
        if net is None:
            print(f"  [warn] scope entry '{entry}' is not a valid IP/CIDR — skipped", file=sys.stderr)
            continue
        scope_networks.append((entry, net))

    live_addresses: list[tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]] = []
    for entry in live_assets:
        try:
            live_addresses.append((entry, ipaddress.ip_address(entry)))
        except (ValueError, TypeError):
            print(f"  [warn] live asset entry '{entry}' is not a valid IP — skipped", file=sys.stderr)
            continue

    issues: list[ScopeIssue] = []

    for entry, net in scope_networks:
        if not any(addr in net for _, addr in live_addresses):
            issues.append(ScopeIssue(
                "uncovered_scope", entry,
                f"{entry} is authorised scope but no live asset falls within "
                f"it — it may not be getting scanned",
            ))

    for entry, addr in live_addresses:
        if not any(addr in net for _, net in scope_networks):
            issues.append(ScopeIssue(
                "out_of_scope_asset", entry,
                f"{entry} is a live scanned asset but is not covered by any "
                f"authorised scope entry",
            ))

    for hostname in scope.get("hostnames") or []:
        issues.append(ScopeIssue(
            "unverified_hostname", hostname,
            f"hostname '{hostname}' requires DNS resolution to verify "
            f"against live asset IPs — check manually",
        ))

    return issues


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_scope_report(
    issues: list[ScopeIssue],
    scope_label: str,
    live_label: str,
    use_color: bool = True,
) -> None:
    """Print a human-readable scope audit report to stdout.

    Follows the same +/- convention as print_diff(), with scope as the
    baseline ("golden") and live assets as "current":
        +  out-of-scope asset  (green) — present in current, not golden
        -  uncovered scope     (red)   — present in golden, not current
    Hostnames needing manual DNS verification are shown separately, marked
    "~" (neutral), since they're not a confirmed discrepancy either way.
    """
    sep = "=" * 64

    print(f"\n{sep}")
    print("  Asset Scope Audit")
    print(f"  Scope (authorised) : {scope_label}")
    print(f"  Live (scanned)      : {live_label}")
    print(f"{sep}\n")

    if not issues:
        print(_c("  RESULT: PASS - no scope discrepancies found", _GREEN, use_color))
        print(sep)
        return

    uncovered    = [i for i in issues if i.category == "uncovered_scope"]
    out_of_scope = [i for i in issues if i.category == "out_of_scope_asset"]
    unverified   = [i for i in issues if i.category == "unverified_hostname"]

    if uncovered:
        print(f"Uncovered scope ({len(uncovered)}) — authorised but no matching live asset:")
        for issue in uncovered:
            print(_c(f"  - {issue.entry}", _RED, use_color))
            print(f"      {issue.message}")
        print()

    if out_of_scope:
        print(f"Out-of-scope assets ({len(out_of_scope)}) — scanned but not authorised:")
        for issue in out_of_scope:
            print(_c(f"  + {issue.entry}", _GREEN, use_color))
            print(f"      {issue.message}")
        print()

    if unverified:
        print(f"Hostnames requiring manual verification ({len(unverified)}):")
        for issue in unverified:
            print(_c(f"  ~ {issue.entry}", _YELLOW, use_color))
            print(f"      {issue.message}")
        print()

    print(sep)
    print(_c(f"  RESULT: FAIL - {len(issues)} issue(s) found", _BOLD + _RED, use_color))
    print(sep)


def write_scope_report(issues: list[ScopeIssue], path: str | Path) -> None:
    """Serialise the scope audit findings to a JSON file."""
    Path(path).write_text(
        json.dumps([asdict(i) for i in issues], indent=2),
        encoding="utf-8",
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def _add_policy_subparser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "policy",
        help="Diff a live scan policy configuration against a golden-copy XML baseline.",
    )
    parser.add_argument(
        "--golden", "-g", required=True,
        help="Path to the golden-copy baseline configuration (XML file).",
    )
    parser.add_argument(
        "--current", "-c", default=None,
        help=(
            "Path to the live scan policy configuration (JSON file). "
            "Omit to read JSON from stdin (e.g. piped from tenable_sc.py)."
        ),
    )
    parser.add_argument(
        "--index", "-i", type=int, default=None,
        help=(
            "If --current (or stdin) contains multiple scan policies — a "
            "bare list, or scan_policies.json's {\"scan_policies\": [...], "
            "\"assets\": [...]} blob — select this zero-based index."
        ),
    )
    parser.add_argument(
        "--out", "-o", default="audit_report.json",
        help="Path for the structured JSON diff report (default: audit_report.json).",
    )
    parser.add_argument(
        "--exclude-path", "-e", action="append", default=[],
        metavar="PATH",
        help=(
            "DeepDiff root-style path to exclude from comparison, e.g. "
            "\"root['startTime']\". Repeatable."
        ),
    )
    parser.add_argument(
        "--strict-order", action="store_true",
        help="Treat list/array element order as significant (default: ignored).",
    )
    parser.add_argument(
        "--infer-types", action="store_true",
        help=(
            "Coerce golden XML leaf text to bool/int/float where possible. "
            "Off by default — see the module docstring for why."
        ),
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in the stdout report.",
    )


def _run_policy_audit(args: argparse.Namespace) -> None:
    try:
        golden  = xml_to_dict(args.golden, infer_types=args.infer_types)
        current = load_current_config(args.current, args.index)
    except (FileNotFoundError, ValueError, ET.ParseError) as exc:
        sys.exit(f"Error: {exc}")

    diff = compare_configs(
        golden, current,
        ignore_order=not args.strict_order,
        exclude_paths=args.exclude_path,
    )

    current_label = args.current or "<stdin>"
    print_diff(diff, args.golden, current_label, use_color=not args.no_color)

    try:
        write_diff(diff, args.out)
    except OSError as exc:
        sys.exit(f"Error: failed to write {args.out}: {exc}")
    print(f"\nFull report written to {args.out}")

    sys.exit(1 if diff else 0)


def _add_scope_subparser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "scope",
        help=(
            "Compare tenable_sc.py's live asset IPs against scope_extractor.py's "
            "authorised scope."
        ),
    )
    parser.add_argument(
        "--golden", "-g", required=True,
        help="Path to scope_extractor.py's output (YAML or JSON) — the authorised scope.",
    )
    parser.add_argument(
        "--current", "-c", default=None,
        help=(
            "Path to tenable_sc.py's output (scan_policies.json) or a bare JSON "
            "array of IPs. Omit to read JSON from stdin."
        ),
    )
    parser.add_argument(
        "--out", "-o", default="scope_audit_report.json",
        help="Path for the structured JSON findings report (default: scope_audit_report.json).",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in the stdout report.",
    )


def _run_scope_audit(args: argparse.Namespace) -> None:
    try:
        scope       = load_scope_file(args.golden)
        live_assets = load_live_assets(args.current)
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(f"Error: {exc}")

    issues = compare_scope(live_assets, scope)

    current_label = args.current or "<stdin>"
    print_scope_report(issues, args.golden, current_label, use_color=not args.no_color)

    try:
        write_scope_report(issues, args.out)
    except OSError as exc:
        sys.exit(f"Error: failed to write {args.out}: {exc}")
    print(f"\nFull report written to {args.out}")

    sys.exit(1 if issues else 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit a Tenable Security Center deployment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_policy_subparser(subparsers)
    _add_scope_subparser(subparsers)
    args = parser.parse_args()

    if args.command == "policy":
        _run_policy_audit(args)
    elif args.command == "scope":
        _run_scope_audit(args)


if __name__ == "__main__":
    main()
