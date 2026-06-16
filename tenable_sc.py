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

Scan policy vs. scan vs. scan result
-------------------------------------
Security Center has three distinct, easily-confused object types — this
module deliberately pulls the first one:
    Scan policy  (/rest/policy)      – a reusable template of scan settings:
                                        preferences, plugin family selection,
                                        audit files.  No targets, no schedule.
    Scan         (/rest/scan)        – a configured scan: references a
                                        policy plus targets, a schedule, a
                                        repository, a zone, etc.
    Scan result  (/rest/scanResult)  – one executed run of a scan: status,
                                        start/finish time, IP/check counts.
Confirmed against the Tenable Security Center API docs
(docs.tenable.com/security-center/api/Scan-Policy.htm) and by inspecting the
installed pyTenable source (tenable.sc.policies.ScanPolicyAPI): GET /policy
returns only summary fields (name, description, status, policyTemplate,
creator, ...); the full configuration — preferences, auditFiles, and (for
Advanced Scan/Audit templates) the families plugin-family selection — is
only present in the GET /policy/{id} response.  collect_scan_policy_configs()
below fetches the summary list first to discover every policy ID, then
requests full details for each one so the output actually reflects each
policy's configuration rather than just its name and status.

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
    # Writes scan_policies.json — a JSON array with one entry per configured
    # scan policy, each containing that policy's full configuration.

Extending:
    pyTenable exposes one namespace per SC API object on the TenableSC
    instance, e.g.:
        sc.policies        – scan policies            (/rest/policy)
        sc.scans           – scan definitions          (/rest/scan)
        sc.scan_instances  – scan results/instances    (/rest/scanResult)
        sc.repositories    – vulnerability repositories
        sc.scan_zones      – scanner-to-IP-range mappings
        sc.organizations   – organisations
        sc.credentials     – stored credentials
    Add a method to SecurityCenterClient that calls the relevant namespace
    and shapes the result the way callers need.  Pagination, auth, and
    retries are handled by pyTenable — there is no need to reimplement them.
"""

import json
import os
import sys
from typing import Any

from dotenv import load_dotenv
from tenable.errors import RestflyException
from tenable.sc import TenableSC

# ── Initialisation ────────────────────────────────────────────────────────────

load_dotenv()  # pull variables from .env if present


# ── Client ────────────────────────────────────────────────────────────────────

class SecurityCenterClient:
    """Thin wrapper around pyTenable's TenableSC client.

    Public interface
    -----------------
    get_scan_policies            – every scan policy, summary fields only
    get_scan_policy_details      – one scan policy's full configuration
    collect_scan_policy_configs  – every scan policy's full configuration
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

    # ── Scan policies ─────────────────────────────────────────────────────────

    def get_scan_policies(self) -> list[dict[str, Any]]:
        """Return every configured scan policy as a flat list of summaries.

        Wraps GET /policy via pyTenable's sc.policies.list(), which returns a
        dict split into "usable" (every policy visible to this API user) and
        "manageable" (the subset this user can edit).  "usable" is the
        superset and is preferred; "manageable" is only used as a fallback
        for accounts where "usable" is absent.

        Note: per the SC API docs, GET /policy only returns summary fields
        (name, description, status, policyTemplate, creator, ...) — it does
        NOT include preferences, auditFiles, or families.  Use
        get_scan_policy_details() or collect_scan_policy_configs() for the
        full configuration of a policy.
        """
        data = self._sc.policies.list()
        return data.get("usable") or data.get("manageable") or []

    def get_scan_policy_details(self, policy_id: int | str) -> dict[str, Any]:
        """Return the full configuration of one scan policy, by ID.

        Wraps GET /policy/{id} via pyTenable's sc.policies.details(), which
        — unlike the summary list endpoint — includes preferences,
        auditFiles, and (for Advanced Scan/Audit templates only) the
        families plugin-family selection.
        """
        return self._sc.policies.details(int(policy_id))

    def collect_scan_policy_configs(self) -> list[dict[str, Any]]:
        """Return the full configuration of every scan policy Security Center
        knows about.

        GET /policy only returns summary fields; this fetches that summary
        list first to discover every policy ID, then requests full details
        (GET /policy/{id}) for each one, so each entry in the returned list
        is a complete policy configuration rather than just its name/status.

        If a given policy's details call fails (e.g. a permissions error on
        one policy), that one entry becomes {"id", "name", "error"} and
        collection continues — one bad policy should not discard every other
        policy's configuration that was already retrieved.
        """
        configs: list[dict[str, Any]] = []

        for policy in self.get_scan_policies():
            try:
                configs.append(self.get_scan_policy_details(policy["id"]))
                print(f"  [ok]  policy {policy['id']} ({policy.get('name')})")
            except RestflyException as exc:
                configs.append({
                    "id":    policy.get("id"),
                    "name":  policy.get("name"),
                    "error": str(exc),
                })
                print(
                    f"  [err] policy {policy.get('id')} ({policy.get('name')}): {exc}",
                    file=sys.stderr,
                )

        return configs


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

    print(f"Collecting scan policy configurations from {host} ...")
    scan_policies = client.collect_scan_policy_configs()

    output_path = "scan_policies.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(scan_policies, fh, indent=2, default=str)

    print(f"  {len(scan_policies)} scan policy configuration(s) found")
    print(f"\nReport written to {output_path}")


if __name__ == "__main__":
    main()
