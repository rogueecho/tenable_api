"""
audit.py
--------
Audits a live Tenable Security Center scan policy configuration (JSON)
against a golden-copy baseline (XML) using DeepDiff.

A "scan policy" here means the object returned by GET /policy/{id} — a
reusable template of scan preferences, audit files, and plugin family
selections.  It is distinct from a "scan" (which adds targets/schedule/
repository on top of a policy) and a "scan result" (one executed run).  See
the docstring in tenable_sc.py for the full distinction.

Inputs
------
  golden   – an XML file describing the known-good configuration of one
             scan policy.  Nested elements map to nested dict keys;
             repeated sibling elements with the same tag collapse into a
             list.  Leaf text is kept as a plain string by default (see
             --infer-types) because the SC REST API returns nearly every
             policy field — including numbers and booleans — as a string;
             coercing types here would manufacture spurious discrepancies
             against that live data.

  current  – the live configuration of a single scan policy as JSON, i.e.
             one entry from the list returned by
             tenable_sc.SecurityCenterClient.collect_scan_policy_configs().
             Read from a file (--current) or from stdin (pipe it straight
             out of tenable_sc.py).  If the JSON is an array of policies
             rather than a single object, --index selects which entry to
             audit.

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
    python audit.py --golden golden_scan_policy.xml --current scan_policy.json

    # Pipe straight from tenable_sc.py and pick one entry out of the array
    python tenable_sc.py
    python audit.py --golden golden_scan_policy.xml --current scan_policies.json --index 0
    type scan_policies.json | python audit.py --golden golden_scan_policy.xml --index 0

    # Ignore fields that are expected to change between runs
    python audit.py --golden golden_scan_policy.xml --current scan_policy.json ^
        --exclude-path "root['modifiedTime']"

Exit codes:
    0  – no discrepancies found
    1  – one or more discrepancies found
    (a malformed/missing input exits non-zero via sys.exit(<message>))

Extending:
    New comparison knobs (significant_digits, exclude_regex_paths, etc.) can
    be threaded through compare_configs() — see the DeepDiff documentation
    for the full option set.
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import colorama
import defusedxml.ElementTree as DET
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

    Accepts either a single scan policy object, or a list of them (as
    produced by tenable_sc.SecurityCenterClient.collect_scan_policy_configs()),
    in which case `index` selects which entry to use.
    """
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


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit a live Tenable Security Center scan policy configuration "
            "(JSON) against a golden-copy baseline (XML) using DeepDiff."
        ),
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
            "If --current (or stdin) is a JSON array of scan policies "
            "(e.g. scan_policies.json), select this zero-based index."
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
    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
