"""
tenable_sc.py
-------------
Client for the Tenable Security Center REST API.

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

Extending:
    Add a new method to SecurityCenterClient that calls self._get() with the
    desired endpoint path, then call it from collect_config_report() or your
    own script.
"""

import json
import os
import sys
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv

# ── Initialisation ────────────────────────────────────────────────────────────

load_dotenv()  # pull variables from .env if present


# ── Client ────────────────────────────────────────────────────────────────────

class SecurityCenterClient:
    """Thin wrapper around the Tenable Security Center REST API.

    All public methods return the parsed JSON body (dict or list) that the API
    sends back under the "response" key, or raise RuntimeError on failure.

    To add a new endpoint, add a method that calls self._get() (or self._post()
    for write operations) and return the result.  Then call that method from
    collect_config_report() if it should be part of the standard report.
    """

    # Fields requested by default when listing multi-record resources.
    # Explicitly requesting fields avoids overly large payloads.
    _SCANNER_FIELDS    = "id,name,description,ip,port,status,version,type"
    _REPOSITORY_FIELDS = "id,name,description,type,dataFormat,ipCount,lastVulnUpdate"
    _ORG_FIELDS        = "id,name,description,userCount,lceCount,scannerCount"
    _ZONE_FIELDS       = "id,name,description,ipList,activeScanners,totalScanners"
    _USER_FIELDS       = "id,username,firstname,lastname,role,group,lastLogin"

    def __init__(
        self,
        host: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        """
        Args:
            host:       Hostname / IP of the Security Center appliance.
            access_key: API access key from Security Center.
            secret_key: API secret key from Security Center.
            verify_ssl: Set False only in lab environments with self-signed certs.
            timeout:    Request timeout in seconds.
        """
        self._base_url = f"https://{host}/rest"
        self._timeout  = timeout
        self._verify   = verify_ssl

        # Security Center API key auth header format (SC 5.13+)
        self._session = requests.Session()
        self._session.headers.update({
            "X-APIKey":     f"accesskey={access_key};secretkey={secret_key}",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

        if not verify_ssl:
            # Suppress the InsecureRequestWarning that urllib3 emits per-request
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> Any:
        """Send a GET request and return the parsed 'response' payload.

        Args:
            path:   API path relative to /rest (e.g. "/system").
            params: Optional query-string parameters.

        Returns:
            The value of response["response"], which may be a dict or list.

        Raises:
            RuntimeError: If the HTTP request fails or the API returns an error.
        """
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.get(
                url, params=params, timeout=self._timeout, verify=self._verify
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed [{path}]: {exc}") from exc

        body = resp.json()

        # Security Center wraps successful payloads in {"type":"regular","response":{...}}
        if body.get("type") == "error":
            raise RuntimeError(
                f"API error [{path}]: {body.get('error_code')} – {body.get('error_msg')}"
            )

        return body.get("response", body)

    def _post(self, path: str, payload: dict) -> Any:
        """Send a POST request and return the parsed 'response' payload.

        Add write-capable endpoints (e.g. scan launch, policy create) by
        calling this helper.
        """
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.post(
                url, json=payload, timeout=self._timeout, verify=self._verify
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed [{path}]: {exc}") from exc

        body = resp.json()
        if body.get("type") == "error":
            raise RuntimeError(
                f"API error [{path}]: {body.get('error_code')} – {body.get('error_msg')}"
            )
        return body.get("response", body)

    # ── System / platform ─────────────────────────────────────────────────────

    def get_system_info(self) -> dict:
        """Return platform metadata: version, build date, license info."""
        return self._get("/system")

    def get_config(self) -> dict:
        """Return the platform configuration block (SMTP, auth settings, etc.)."""
        return self._get("/config")

    def get_status(self) -> dict:
        """Return feed/plugin update status (active plugins count, last update)."""
        return self._get("/status")

    def get_current_user(self) -> dict:
        """Return details about the authenticated API user."""
        return self._get("/currentUser", params={"fields": self._USER_FIELDS})

    def get_ip_info(self) -> dict:
        """Return licensed IP counts and current usage."""
        return self._get("/ipInfo")

    # ── Infrastructure ────────────────────────────────────────────────────────

    def get_scanners(self) -> list:
        """Return all Nessus scanners registered to this Security Center."""
        return self._get("/scanner", params={"fields": self._SCANNER_FIELDS})

    def get_repositories(self) -> list:
        """Return all vulnerability data repositories."""
        return self._get("/repository", params={"fields": self._REPOSITORY_FIELDS})

    def get_scan_zones(self) -> list:
        """Return all scan zones (scanner-to-IP-range mappings)."""
        return self._get("/zone", params={"fields": self._ZONE_FIELDS})

    # ── Organisational ────────────────────────────────────────────────────────

    def get_organizations(self) -> list:
        """Return all organisations defined in Security Center."""
        return self._get("/organization", params={"fields": self._ORG_FIELDS})

    # ── Compound report ───────────────────────────────────────────────────────

    def collect_config_report(self) -> dict:
        """Gather configuration data from all relevant endpoints.

        Returns a dict keyed by section name.  Add new sections here by calling
        additional get_*() methods and assigning the result to a new key.
        """
        sections: dict[str, Any] = {}

        tasks = [
            ("system_info",   self.get_system_info),
            ("config",        self.get_config),
            ("status",        self.get_status),
            ("current_user",  self.get_current_user),
            ("ip_info",       self.get_ip_info),
            ("scanners",      self.get_scanners),
            ("repositories",  self.get_repositories),
            ("scan_zones",    self.get_scan_zones),
            ("organizations", self.get_organizations),
            # ── Add new sections here ──────────────────────────────────────
            # ("plugin_families", self.get_plugin_families),
        ]

        for section_name, method in tasks:
            try:
                sections[section_name] = method()
                print(f"  [ok]  {section_name}")
            except RuntimeError as exc:
                # Record the error inline so a single failure doesn't abort
                # the whole report
                sections[section_name] = {"error": str(exc)}
                print(f"  [err] {section_name}: {exc}", file=sys.stderr)

        return sections


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    # Read credentials from environment (loaded from .env by load_dotenv above)
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

    print(f"Collecting configuration from {host} …")
    report = client.collect_config_report()

    # Write the full report to a JSON file for inspection / archiving
    output_path = "sc_config_report.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"\nReport written to {output_path}")


if __name__ == "__main__":
    main()
