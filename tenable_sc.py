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
    1. Simple JSON endpoint  → add a method calling self._get() or self._post().
    2. Paginated GET endpoint → call self._get_all_pages().
    3. Analysis/vuln query   → call self._post_all_pages() (handles unknown totals).
    4. Binary download       → call self._stream_download().
    5. File upload           → call self._upload_file_multipart().

    Register new config-report sections in collect_config_report().

Chunking / pagination notes
---------------------------
POST /analysis
    Always paginated.  The API accepts startOffset + endOffset per request and
    returns totalRecords / returnedRecords.  matchingDataElementCount may be the
    string "-1", meaning the server does not know the total until all pages are
    consumed.  _post_all_pages() handles both the known-total and unknown-total
    cases by stopping when a page shorter than the requested window is returned.

GET endpoints with paginated=true (e.g. /report)
    Pass paginated=true plus startOffset/endOffset.  Response includes
    totalRecords so the loop can stop early once all records are collected.
    _get_all_pages() handles this automatically.

Binary downloads (/report/{id}/download, /analysis/download)
    The response body is raw bytes (PDF, RTF, CSV …).  _stream_download()
    writes the response to disk in DOWNLOAD_CHUNK_SIZE increments so the
    entire file is never held in memory.

File uploads (POST /file/upload)
    Standard multipart/form-data.  The session-level Content-Type header
    must be absent so that requests can set the correct multipart boundary.
    _upload_file_multipart() handles this by sending the header only for that
    request via a temporary header override.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv

# ── Initialisation ────────────────────────────────────────────────────────────

load_dotenv()  # pull variables from .env if present

# Rows fetched per round-trip for paginated endpoints.
PAGE_SIZE = 1000

# Bytes read per iteration when streaming a binary download to disk (8 MiB).
DOWNLOAD_CHUNK_SIZE = 8 * 1024 * 1024


# ── Client ────────────────────────────────────────────────────────────────────

class SecurityCenterClient:
    """Wrapper around the Tenable Security Center REST API.

    All public methods return parsed Python objects (dict or list) or write
    files to disk.  They raise RuntimeError on HTTP or API-level failures.

    Public interface by category
    ----------------------------
    System / platform  : get_system_info, get_config, get_status,
                         get_current_user, get_ip_info
    Infrastructure     : get_scanners, get_repositories, get_scan_zones
    Organisational     : get_organizations
    Analysis / vulns   : query_analysis, download_analysis_csv
    Reports            : get_reports, download_report
    File management    : upload_file, clear_file
    Compound           : collect_config_report
    """

    # Default field lists – explicit field selection avoids unnecessary payload
    # size and future-proofs against new fields that break downstream parsers.
    _SCANNER_FIELDS    = "id,name,description,ip,port,status,version,type"
    _REPOSITORY_FIELDS = "id,name,description,type,dataFormat,ipCount,lastVulnUpdate"
    _ORG_FIELDS        = "id,name,description,userCount,lceCount,scannerCount"
    _ZONE_FIELDS       = "id,name,description,ipList,activeScanners,totalScanners"
    _USER_FIELDS       = "id,username,firstname,lastname,role,group,lastLogin"
    _REPORT_FIELDS     = "id,name,description,type,status,startTime,finishTime,owner"

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
            access_key: API access key generated in Security Center.
            secret_key: API secret key generated in Security Center.
            verify_ssl: Set False only for lab appliances with self-signed certs.
            timeout:    Per-request timeout in seconds (not used for streaming).
        """
        self._base_url = f"https://{host}/rest"
        self._timeout  = timeout
        self._verify   = verify_ssl

        self._session = requests.Session()
        # Documented header format: accesskey=X; secretkey=Y; (spaces + trailing ;)
        self._session.headers.update({
            "x-apikey":     f"accesskey={access_key}; secretkey={secret_key};",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_body(self, resp: requests.Response, path: str) -> Any:
        """Raise on API-level errors and return the 'response' payload."""
        body = resp.json()
        if body.get("type") == "error":
            raise RuntimeError(
                f"API error [{path}]: {body.get('error_code')} - {body.get('error_msg')}"
            )
        return body.get("response", body)

    def _get(self, path: str, params: dict | None = None) -> Any:
        """Single GET request → parsed 'response' payload."""
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.get(
                url, params=params, timeout=self._timeout, verify=self._verify
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed [{path}]: {exc}") from exc
        return self._parse_body(resp, path)

    def _post(self, path: str, payload: dict) -> Any:
        """Single POST request → parsed 'response' payload."""
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.post(
                url, json=payload, timeout=self._timeout, verify=self._verify
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed [{path}]: {exc}") from exc
        return self._parse_body(resp, path)

    def _get_all_pages(
        self,
        path: str,
        params: dict | None = None,
        page_size: int = PAGE_SIZE,
    ) -> list:
        """Paginate through a GET endpoint that supports SC offset pagination.

        Sends repeated requests advancing startOffset/endOffset by page_size
        until either the known totalRecords is exhausted or a short page (fewer
        records than requested) signals the final page.

        SC list endpoints return either:
          • {"usable": [...], "manageable": [...], "totalRecords": N, ...}
          • a plain list (uncommon but handled)

        Only "usable" records are returned; "manageable" is a subset that
        would introduce duplicates if merged.

        Args:
            path:      API path (e.g. "/report").
            params:    Base query-string parameters; pagination keys are added.
            page_size: Number of records per request.

        Returns:
            Flat list of all record dicts.
        """
        params = dict(params or {})
        params.update({
            "paginated":   "true",
            "startOffset": 0,
            "endOffset":   page_size,
        })

        collected: list = []

        while True:
            data = self._get(path, params)

            if isinstance(data, list):
                page = data
                total = -1
            else:
                # "usable" is the full visible set; "manageable" is a subset.
                page  = data.get("usable") or data.get("manageable") or []
                total = int(data.get("totalRecords", -1))

            collected.extend(page)

            if total != -1 and len(collected) >= total:
                break
            if len(page) < page_size:   # short page → this was the last one
                break

            params["startOffset"] += page_size
            params["endOffset"]   += page_size

        return collected

    def _post_all_pages(
        self,
        path: str,
        payload: dict,
        page_size: int = PAGE_SIZE,
    ) -> tuple[list, int]:
        """Paginate through a POST endpoint using SC offset pagination.

        Designed for POST /analysis, which:
          • requires startOffset + endOffset in the request body
          • returns totalRecords / returnedRecords in the response
          • may return matchingDataElementCount as the string "-1" when the
            server cannot determine the total count up front

        Both the known-total and unknown-total cases are handled.  Iteration
        stops when either:
          • len(collected) >= totalRecords  (known total), or
          • returnedRecords < page_size     (short page → last page)

        Args:
            path:      API path (e.g. "/analysis").
            payload:   Request body; startOffset/endOffset are injected/updated.
            page_size: Number of records per request.

        Returns:
            (all_results, total) where total is -1 if the server never
            reported a definitive count.
        """
        payload    = dict(payload)
        offset     = 0
        collected: list = []
        known_total     = -1

        while True:
            payload["startOffset"] = offset
            payload["endOffset"]   = offset + page_size

            data     = self._post(path, payload)
            page     = data.get("results", [])
            returned = int(data.get("returnedRecords", len(page)))

            # totalRecords and matchingDataElementCount arrive as strings.
            raw_total = data.get("totalRecords", "-1")
            if known_total == -1 and str(raw_total) != "-1":
                known_total = int(raw_total)

            collected.extend(page)
            offset += returned

            if known_total != -1 and offset >= known_total:
                break
            if returned < page_size:   # server returned fewer than requested
                break

        return collected, known_total

    def _stream_download(
        self,
        method: str,
        path: str,
        dest_path: str | Path,
        json_payload: dict | None = None,
    ) -> Path:
        """Stream a binary response to disk without loading it into memory.

        Used for /report/{id}/download (PDF/CSV/etc.) and /analysis/download
        (CSV), both of which return raw bytes rather than a JSON envelope.

        Args:
            method:       "GET" or "POST".
            path:         API path.
            dest_path:    Local file path to write.
            json_payload: Request body for POST requests.

        Returns:
            Path of the written file.
        """
        url  = f"{self._base_url}{path}"
        dest = Path(dest_path)

        try:
            resp = self._session.request(
                method,
                url,
                json=json_payload,
                stream=True,           # do not buffer the response body
                timeout=self._timeout,
                verify=self._verify,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Download failed [{path}]: {exc}") from exc

        # A JSON error envelope instead of binary means the request itself failed.
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            raise RuntimeError(
                f"Download [{path}] returned JSON (expected binary): "
                f"{resp.text[:200]}"
            )

        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                if chunk:  # filter keep-alive empty chunks
                    fh.write(chunk)

        return dest

    def _upload_file_multipart(
        self,
        file_path: str | Path,
        context: str | None = None,
    ) -> dict:
        """POST a file to /file/upload using multipart/form-data.

        The session carries Content-Type: application/json by default.
        Passing files= to requests replaces that header with the correct
        multipart/form-data boundary for this single request only, so no
        permanent session mutation is needed.

        Args:
            file_path: Local path to the file to upload.
            context:   Optional SC context hint: "auditfile" or "tailoringfile".

        Returns:
            API response dict with 'filename' (server-assigned identifier used
            to reference the upload in subsequent API calls) and
            'originalFilename'.
        """
        path = "/file/upload"
        url  = f"{self._base_url}{path}"
        src  = Path(file_path)

        data: dict = {}
        if context:
            data["context"] = context

        try:
            with open(src, "rb") as fh:
                resp = self._session.post(
                    url,
                    # files= causes requests to set Content-Type: multipart/form-data
                    # with the correct boundary, overriding the session-level JSON header
                    # for this request only.
                    files={"Filedata": (src.name, fh)},
                    data=data,
                    timeout=self._timeout,
                    verify=self._verify,
                )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Upload failed [{path}]: {exc}") from exc

        return self._parse_body(resp, path)

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

    # ── Analysis / vulnerability queries ─────────────────────────────────────

    def query_analysis(
        self,
        query: dict,
        analysis_type: str = "vuln",
        source_type: str = "cumulative",
        sort_field: str = "severity",
        sort_dir: str = "DESC",
        scan_id: int | None = None,
        view: str | None = None,
        page_size: int = PAGE_SIZE,
    ) -> tuple[list, int]:
        """Run an analysis query and page through all results.

        POST /analysis is always paginated – there is no single-shot variant.
        This method transparently fetches every page and returns the full result
        set along with the total record count reported by the server.

        Args:
            query:         SC query object.  Must contain at minimum:
                               {"type": "vuln", "tool": "listvuln", "filters": []}
                           See GET /query for saved-query objects.
            analysis_type: "vuln", "event", "user", "scLog", or "mobile".
            source_type:   For vuln: "cumulative" (default), "individual",
                           "patched".  For event: "lce" or "archive".
            sort_field:    Field name to sort results by.
            sort_dir:      "ASC" or "DESC".
            scan_id:       Required when source_type is "individual".
            view:          Required when source_type is "individual"
                           ("all", "new", "patched") or "archive" (silo id).
            page_size:     Records per request (default PAGE_SIZE).

        Returns:
            (results, total) – total is -1 when the server never reported a
            definitive count (matchingDataElementCount == "-1").

        Example – list all critical/high vulnerabilities::

            results, total = client.query_analysis({
                "type": "vuln",
                "tool": "listvuln",
                "filters": [
                    {"filterName": "severity", "operator": "=", "value": "3,4"}
                ],
            })
        """
        payload: dict[str, Any] = {
            "type":       analysis_type,
            "query":      query,
            "sourceType": source_type,
            "sortField":  sort_field,
            "sortDir":    sort_dir,
        }
        if scan_id is not None:
            payload["scanID"] = scan_id
        if view is not None:
            payload["view"] = view

        return self._post_all_pages("/analysis", payload, page_size=page_size)

    def download_analysis_csv(
        self,
        query: dict,
        columns: list[dict],
        dest_path: str | Path,
        analysis_type: str = "vuln",
        source_type: str = "cumulative",
        sort_field: str = "severity",
        sort_dir: str = "DESC",
        scan_id: int | None = None,
        view: str | None = None,
    ) -> Path:
        """Download an analysis result set as a CSV file.

        POST /analysis/download returns a raw CSV stream (not a JSON envelope).
        The file is written to disk in DOWNLOAD_CHUNK_SIZE increments.

        Args:
            query:       SC query object (same format as query_analysis).
            columns:     List of column dicts, e.g. [{"name": "ip"}, {"name": "pluginID"}].
            dest_path:   Local path for the output CSV file.
            analysis_type, source_type, sort_field, sort_dir, scan_id, view:
                         Same semantics as query_analysis.

        Returns:
            Path of the written CSV file.

        Example::

            path = client.download_analysis_csv(
                query={"type": "vuln", "tool": "listvuln", "filters": []},
                columns=[{"name": "ip"}, {"name": "pluginID"}, {"name": "severity"}],
                dest_path="vulns.csv",
            )
        """
        # startOffset/endOffset are required by the API.  Set endOffset to a
        # value large enough to cover any realistic result set so the caller
        # receives the complete dataset without needing to paginate manually.
        payload: dict[str, Any] = {
            "type":        analysis_type,
            "query":       query,
            "sourceType":  source_type,
            "sortField":   sort_field,
            "sortDir":     sort_dir,
            "startOffset": 0,
            "endOffset":   2_000_000_000,
            "columns":     columns,
        }
        if scan_id is not None:
            payload["scanID"] = scan_id
        if view is not None:
            payload["view"] = view

        return self._stream_download("POST", "/analysis/download", dest_path, payload)

    # ── Reports ───────────────────────────────────────────────────────────────

    def get_reports(
        self,
        status: str | None = None,
        page_size: int = PAGE_SIZE,
    ) -> list:
        """Return all report records, paging through as many pages as needed.

        GET /report supports an optional paginated=true mode.  Without it the
        API defaults to returning the first 50 records.  This method always
        uses pagination so deployments with large report histories are handled
        correctly.

        Args:
            status:    Optional status filter: "Completed", "Running", etc.
            page_size: Records per request.

        Returns:
            Flat list of report dicts.
        """
        params: dict[str, Any] = {"fields": self._REPORT_FIELDS}
        if status:
            params["status"] = status
        return self._get_all_pages("/report", params=params, page_size=page_size)

    def download_report(
        self,
        report_id: int | str,
        dest_path: str | Path,
    ) -> Path:
        """Download a completed report file to disk.

        POST /report/{id}/download returns raw binary (PDF, RTF, CSV, ASR,
        ARF, or LASR).  The file is streamed in DOWNLOAD_CHUNK_SIZE chunks so
        large PDFs do not need to fit in memory.

        Args:
            report_id: Numeric ID of the completed report.
            dest_path: Local path to write (extension should match report type).

        Returns:
            Path of the written file.
        """
        return self._stream_download(
            "POST", f"/report/{report_id}/download", dest_path
        )

    # ── File management ───────────────────────────────────────────────────────

    def upload_file(
        self,
        file_path: str | Path,
        context: str | None = None,
    ) -> dict:
        """Upload a file to Security Center's temporary upload store.

        The returned 'filename' token must be passed back to the API in
        subsequent create/update calls (e.g. POST /auditFile, POST /credential).

        Two-step workflow::

            upload  = client.upload_file("policy.audit", context="auditfile")
            audit   = client.create_audit_file(
                name="My Policy",
                filename=upload["filename"],
                original_filename=upload["originalFilename"],
            )

        Args:
            file_path: Local path to the file to upload.
            context:   Hint to Security Center: "auditfile" or "tailoringfile".

        Returns:
            dict with at least:
                filename         – server-assigned upload token
                originalFilename – original file name
        """
        return self._upload_file_multipart(file_path, context=context)

    def clear_file(self, filename: str) -> str:
        """Remove a previously uploaded temporary file.

        Call this after a failed create/update so orphaned uploads do not
        accumulate on the appliance.

        Args:
            filename: The 'filename' token returned by upload_file().

        Returns:
            The filename path that was removed (as reported by the API).
        """
        data = self._post("/file/clear", {"filename": filename})
        return data if isinstance(data, str) else data.get("filename", filename)

    # ── Compound report ───────────────────────────────────────────────────────

    def collect_config_report(self) -> dict:
        """Gather configuration data from all relevant endpoints.

        Returns a dict keyed by section name.  Each section is either the
        parsed API payload or {"error": "<message>"} if that endpoint failed
        (so one failure does not abort the whole report).

        To add a new section:
            1. Add a method (or inline lambda) to the tasks list below.
            2. The key becomes the section name in the output JSON.
        """
        sections: dict[str, Any] = {}

        tasks: list[tuple[str, Any]] = [
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
            # ("reports",         self.get_reports),
        ]

        for section_name, method in tasks:
            try:
                sections[section_name] = method()
                print(f"  [ok]  {section_name}")
            except RuntimeError as exc:
                sections[section_name] = {"error": str(exc)}
                print(f"  [err] {section_name}: {exc}", file=sys.stderr)

        return sections


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

    print(f"Collecting configuration from {host} …")
    report = client.collect_config_report()

    output_path = "sc_config_report.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"\nReport written to {output_path}")


if __name__ == "__main__":
    main()
