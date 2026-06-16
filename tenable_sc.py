"""
tenable_sc.py
-------------
Client for the Tenable Security Center API, built on the official pyTenable
SDK (tenable.sc.TenableSC) instead of hand-rolled HTTP calls.

pyTenable already handles the x-apikey auth header, SC offset pagination,
retries, and SSL-warning suppression internally, so this module no longer
needs the custom _get/_post/_get_all_pages/_stream_download machinery that
the previous requests-based implementation carried.  It just wraps the calls
this project needs and shapes the output the way the rest of the toolkit
expects.

Authentication uses API key pairs (Access Key + Secret Key), available in
Security Center 5.13+.  Credentials are read from environment variables so
they never live in source code.

Environment variables (see .env.example):
    SC_HOST        – Hostname or IP of the Security Center appliance
    SC_ACCESS_KEY  – API access key
    SC_SECRET_KEY  – API secret key
    SC_VERIFY_SSL  – "false" to disable SSL verification (default: true)

Usage:
    python tenable_sc.py
    # Writes scan_instances.json — a JSON array with one entry per scan
    # instance (scan result) Security Center knows about.

Extending:
    pyTenable exposes one namespace per SC API object on the TenableSC
    instance, e.g.:
        sc.scans          – scan definitions       (/rest/scan)
        sc.scan_instances – scan results/instances  (/rest/scanResult)
        sc.repositories    – vulnerability repositories
        sc.scan_zones      – scanner-to-IP-range mappings
        sc.organizations   – organisations
        sc.policies         – scan policies
        sc.credentials      – stored credentials
    Add a method to SecurityCenterClient that calls the relevant namespace
    and shapes the result the way callers need.  Pagination, auth, and
    retries are handled by pyTenable — there is no need to reimplement them.
"""

import json
import os
import sys
from typing import Any

from dotenv import load_dotenv
from tenable.sc import TenableSC

# ── Initialisation ────────────────────────────────────────────────────────────

load_dotenv()  # pull variables from .env if present


# ── Client ────────────────────────────────────────────────────────────────────

class SecurityCenterClient:
    """Thin wrapper around pyTenable's TenableSC client.

    Public interface
    -----------------
    get_scan_instances – every scan instance (scan result) as a flat list
    """

    def __init__(
        self,
        host: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = True,
    ) -> None:
        """
        Args:
            host:       Hostname / IP of the Security Center appliance.
            access_key: API access key generated in Security Center.
            secret_key: API secret key generated in Security Center.
            verify_ssl: Set False only for lab appliances with self-signed certs.
        """
        # TenableSC authenticates immediately when access_key/secret_key are
        # supplied to the constructor — no separate login() call is needed.
        self._sc = TenableSC(
            url=f"https://{host}",
            access_key=access_key,
            secret_key=secret_key,
            ssl_verify=verify_ssl,
        )

    # ── Scan instances ───────────────────────────────────────────────────────

    def get_scan_instances(self) -> list[dict[str, Any]]:
        """Return every scan instance (result of a configured scan) as a flat list.

        Wraps GET /scanResult via pyTenable's sc.scan_instances.list(), which
        returns a dict split into "usable" (every instance visible to this
        API user) and "manageable" (the subset this user can manage/edit).
        "usable" is the superset and is preferred; "manageable" is only used
        as a fallback for accounts where "usable" is absent.
        """
        data = self._sc.scan_instances.list()
        return data.get("usable") or data.get("manageable") or []


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    host       = os.getenv("SC_HOST", "")
    access_key = os.getenv("SC_ACCESS_KEY", "")
    secret_key = os.getenv("SC_SECRET_KEY", "")
    verify_ssl = os.getenv("SC_VERIFY_SSL", "true").lower() != "false"

    if not all([host, access_key, secret_key]):
        sys.exit(
            "Error: SC_HOST, SC_ACCESS_KEY, and SC_SECRET_KEY must be set.\n"
            "Copy .env.example to .env and fill in your credentials."
        )

    client = SecurityCenterClient(
        host=host,
        access_key=access_key,
        secret_key=secret_key,
        verify_ssl=verify_ssl,
    )

    print(f"Collecting scan instances from {host} ...")
    scan_instances = client.get_scan_instances()

    output_path = "scan_instances.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(scan_instances, fh, indent=2, default=str)

    print(f"  {len(scan_instances)} scan instance(s) found")
    print(f"\nReport written to {output_path}")


if __name__ == "__main__":
    main()
