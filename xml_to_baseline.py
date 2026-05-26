"""
xml_to_baseline.py
------------------
Converts an XML Security Center configuration export into a YAML baseline
compatible with audit.py.

Only the config_checks section is generated.  The scope block (IPs, CIDRs,
hostnames) must be added to the output file manually.

Two XML input styles are supported and may be mixed in the same file:

  1. Nested section elements  (preferred)
     Section tag names must match collect_config_report() keys:
       config | system_info | status | current_user | ip_info

     <config>
       <sessionTimeout>30</sessionTimeout>
       <ldapEnabled>true</ldapEnabled>
     </config>
     <system_info>
       <licenseStatus>Valid</licenseStatus>
     </system_info>

  2. Flat <Setting> attributes
     <Setting name="sessionTimeout" value="30" section="config"/>

  See sample_config.xml for a complete example.

Type inference
--------------
Each field value is classified automatically:
  boolean  – value is "true" or "false" (case-insensitive)
  numeric  – value can be parsed as a float; always written as an exact-match
             check (expected: <value>).  To express a range check, manually
             edit the output YAML and replace 'expected' with 'min' and/or
             'max' (either bound may be omitted for one-sided ranges):
               config.sessionTimeout:
                 type: numeric
                 max: 259200    # must complete within 72 hours (seconds)
  string   – everything else

Usage:
    python xml_to_baseline.py sample_config.xml
    python xml_to_baseline.py sample_config.xml --out prod_baseline.yaml
    python xml_to_baseline.py sample_config.xml --exclude smtpHost,smtpFromAddress
    python xml_to_baseline.py sample_config.xml --description "Q3 2026 baseline"
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml


# ── Constants ─────────────────────────────────────────────────────────────────

# Section tag names that map to collect_config_report() keys.
# Tags with these names are treated as config sections; all other
# capitalised tags (Scope, Metadata, Settings) are handled separately.
KNOWN_SECTIONS: set[str] = {
    "config",
    "system_info",
    "status",
    "current_user",
    "ip_info",
    "scanners",
    "repositories",
    "scan_zones",
    "organizations",
}

# Tags that are structural, not config sections.  These are silently skipped
# during iteration so the converter stays forward-compatible with new elements.
STRUCTURAL_TAGS: set[str] = {"Scope", "Metadata", "Settings", "SecurityCenterConfig"}


# ── Numeric helpers ───────────────────────────────────────────────────────────

def _as_int_or_float(n: float) -> int | float:
    """Return n as int when it is a whole number, otherwise as float."""
    return int(n) if n == int(n) else n


# ── Type inference ────────────────────────────────────────────────────────────

def infer_spec(value: str) -> dict:
    """Infer the baseline spec dict for a raw string value.

    Priority:
      1. Boolean  – "true" / "false" (case-insensitive)
      2. Numeric  – parseable as float; written as exact-match (expected: X)
      3. String   – everything else
    """
    stripped = value.strip()

    if stripped.lower() in ("true", "false"):
        return {"type": "boolean", "expected": stripped.lower() == "true"}

    try:
        return {"type": "numeric", "expected": _as_int_or_float(float(stripped))}
    except ValueError:
        pass

    return {"type": "string", "expected": stripped}


# ── XML parser / converter ────────────────────────────────────────────────────

class XmlToBaselineConverter:
    """Parses a Security Center XML config and produces a baseline dict.

    The returned dict is directly serialisable to YAML that audit.py accepts.
    """

    def __init__(
        self,
        exclude: set[str] | None = None,
    ) -> None:
        """
        Args:
            exclude: Set of bare field names to omit from config_checks
                     (e.g. {"smtpHost", "smtpFromAddress"}).
        """
        self._exclude = exclude or set()

    # ── Public entry point ────────────────────────────────────────────────

    def convert(self, xml_path: Path) -> dict[str, Any]:
        """Parse xml_path and return the baseline dict.

        Raises:
            ET.ParseError  on malformed XML.
            FileNotFoundError if the path does not exist.
        """
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as exc:
            raise ET.ParseError(f"Malformed XML in {xml_path}: {exc}") from exc

        root = tree.getroot()

        config_checks: dict[str, dict] = {}

        for child in root:
            tag = child.tag

            if tag in STRUCTURAL_TAGS:
                pass  # Scope, Metadata, Settings wrapper handled separately
            elif tag in KNOWN_SECTIONS or tag.islower():
                # Nested section element whose tag is a SC report section name
                self._parse_section(child, tag, config_checks)
            # Unrecognised capitalised tags are silently skipped so the
            # converter stays forward-compatible with new XML elements.

        # Also handle a <Settings> block if present
        settings_elem = root.find("Settings")
        if settings_elem is not None:
            self._parse_settings_block(settings_elem, config_checks)

        # Flat <Setting> elements directly under root (no <Settings> wrapper)
        for setting in root:
            if setting.tag == "Setting":
                self._parse_single_setting(setting, config_checks)

        return {
            "version":       "1.0",
            "description":   self._extract_description(root),
            "config_checks": config_checks,
        }

    # ── Section parsers ───────────────────────────────────────────────────

    def _parse_section(
        self,
        element: ET.Element,
        section_name: str,
        out: dict,
    ) -> None:
        """Extract direct child elements as field → spec entries."""
        for field_elem in element:
            name  = field_elem.tag.strip()
            value = (field_elem.text or "").strip()

            if not value or name in self._exclude:
                continue

            key = f"{section_name}.{name}"
            out[key] = infer_spec(value)

    def _parse_settings_block(
        self,
        settings_elem: ET.Element,
        out: dict,
    ) -> None:
        """Handle a <Settings> wrapper containing <Setting> children."""
        for child in settings_elem:
            if child.tag == "Setting":
                self._parse_single_setting(child, out)

    def _parse_single_setting(
        self,
        elem: ET.Element,
        out: dict,
    ) -> None:
        """Extract one <Setting name="X" value="Y" section="Z"/> element."""
        name    = (elem.get("name") or "").strip()
        value   = (elem.get("value") or "").strip()
        section = (elem.get("section") or "config").strip()

        if not name or not value or name in self._exclude:
            return

        key = f"{section}.{name}"
        # Don't overwrite a richer nested-section entry with a flat one.
        if key not in out:
            out[key] = infer_spec(value)

    # ── Metadata ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_description(root: ET.Element) -> str:
        """Return the description from <Metadata><Description>, root attributes,
        or a sensible fallback."""
        # <Metadata><Description>…</Description></Metadata>
        meta = root.find("Metadata")
        if meta is not None:
            desc = meta.findtext("Description")
            if desc and desc.strip():
                return desc.strip()

        # host attribute on the root element
        host = root.get("host")
        exported = root.get("exported", "")
        if host:
            suffix = f" exported {exported}" if exported else ""
            return f"Baseline for {host}{suffix}"

        return "Converted from XML — review and annotate before use"


# ── YAML serialisation ────────────────────────────────────────────────────────

class _QuotedStr(str):
    """Marker class so the YAML dumper emits quoted strings."""


def _quoted_str_representer(dumper: yaml.Dumper, data: _QuotedStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


class _QuotedDumper(yaml.Dumper):
    """yaml.Dumper subclass with the _QuotedStr representer pre-registered.

    Subclassing rather than mutating yaml.Dumper directly ensures the
    representer is scoped to this class and does not permanently modify
    the shared global Dumper used by the rest of the process.
    """


_QuotedDumper.add_representer(_QuotedStr, _quoted_str_representer)


def _build_yaml_str(baseline: dict) -> str:
    """Serialise the baseline dict to a YAML string.

    String expected/description values are wrapped in _QuotedStr so they
    are emitted with double-quotes (matching the hand-authored baseline style).
    Boolean and numeric values use YAML native types.
    """
    quoted_checks: dict[str, Any] = {}
    for key, spec in baseline.get("config_checks", {}).items():
        new_spec = dict(spec)
        if spec.get("type") == "string":
            new_spec["expected"] = _QuotedStr(spec["expected"])
        quoted_checks[key] = new_spec

    out = {
        "version":       _QuotedStr(str(baseline["version"])),
        "description":   _QuotedStr(baseline["description"]),
        "config_checks": quoted_checks,
    }

    return yaml.dump(
        out,
        Dumper=_QuotedDumper,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=88,
    )


def write_baseline(baseline: dict, dest: Path) -> None:
    """Write the baseline dict to dest as YAML with a header comment."""
    header = (
        "# Generated by xml_to_baseline.py - review before use in audit.py\n"
        "# Numeric fields use exact-match 'expected' by default.  To express a\n"
        "# range, replace 'expected' with 'min' and/or 'max' in this file.\n\n"
    )
    dest.write_text(header + _build_yaml_str(baseline), encoding="utf-8")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Convert a Security Center XML config export to an audit.py "
            "baseline YAML file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s sample_config.xml\n"
            "  %(prog)s sample_config.xml --out prod_baseline.yaml\n"
            "  %(prog)s sample_config.xml --tolerance 20%%\n"
            "  %(prog)s sample_config.xml --tolerance 5\n"
            "  %(prog)s sample_config.xml --exclude smtpHost,smtpFromAddress\n"
        ),
    )
    parser.add_argument(
        "xml_file",
        help="Path to the Security Center XML configuration export.",
    )
    parser.add_argument(
        "--out", "-o",
        default=None,
        help=(
            "Output YAML file path.  Defaults to <xml_file_stem>_baseline.yaml "
            "in the same directory."
        ),
    )
    parser.add_argument(
        "--exclude", "-e",
        default="",
        help=(
            "Comma-separated list of field names to omit from config_checks "
            "(e.g. smtpHost,smtpFromAddress,ldapHost)."
        ),
    )
    parser.add_argument(
        "--description", "-d",
        default=None,
        help="Override the baseline description string.",
    )

    args = parser.parse_args()

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        sys.exit(f"Error: file not found: {xml_path}")

    out_path = (
        Path(args.out)
        if args.out
        else xml_path.with_name(xml_path.stem + "_baseline.yaml")
    )

    exclude = {f.strip() for f in args.exclude.split(",") if f.strip()}

    converter = XmlToBaselineConverter(exclude=exclude)

    try:
        baseline = converter.convert(xml_path)
    except (ET.ParseError, FileNotFoundError) as exc:
        sys.exit(f"Error: {exc}")

    if args.description:
        baseline["description"] = args.description

    write_baseline(baseline, out_path)

    n_checks = len(baseline.get("config_checks", {}))

    print(f"Converted: {xml_path}  ->  {out_path}")
    print(f"  config checks : {n_checks}")
    if exclude:
        print(f"  excluded      : {', '.join(sorted(exclude))}")


if __name__ == "__main__":
    main()
