"""Async HTTP clients for Rapid7 InsightVM, InsightIDR, and Metasploit Pro."""

import json
import warnings
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, HTTPException

from rapid7_mcp.config import Settings, get_settings

FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures"

_EMPTY_PAGE = {
    "resources": [],
    "page": {"number": 0, "size": 0, "totalPages": 0, "totalResources": 0},
}


def _load_fixture(name: str) -> dict[str, Any]:
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# InsightVM fixture resolution
# ---------------------------------------------------------------------------


_FIXTURE_RULES: list[tuple[tuple[str, ...], str]] = [
    # Sites
    (("sites",),                             "sites.json"),
    (("sites", "<id>"),                      "site.json"),
    # Asset groups
    (("asset_groups",),                      "asset_groups.json"),
    (("asset_groups", "<id>"),               "asset_group.json"),
    # Assets (sub-routes before plain single for correct priority)
    (("assets", "<id>", "vulnerabilities"),  "asset_vulnerabilities.json"),
    (("assets", "<id>", "tags"),             "asset_tags.json"),
    (("assets", "<id>"),                     "asset.json"),
    # Vulnerabilities
    (("vulnerabilities",),                   "vulnerabilities.json"),
    (("vulnerabilities", "<id>"),            "vulnerability.json"),
    # Scans
    (("scans",),                              "scans.json"),
    (("scans", "<id>"),                       "scan.json"),
    (("scan", "engine"),                      "scan_engines.json"),
    (("scan", "engine", "<id>"),              "scan_engine.json"),
    (("scan",),                               "scans.json"),
    (("scan", "<id>", "stop"),                "scan_stop.json"),
    (("scan", "<id>"),                        "scan.json"),
    # Remediation projects
    (("remediation_projects",),              "remediation_projects.json"),
    (("remediation_projects", "<id>"),       "remediation_project.json"),
    # Reports (sub-routes before plain single)
    (("reports",),                           "reports.json"),
    (("reports", "<id>", "generate"),        "report_generate.json"),
    (("reports", "<id>"),                    "report.json"),
    # Cloud health
    (("admin", "health"),                    "vm_health.json"),
]


def _fixture_match(actual: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    """True if *actual* matches *pattern*, where ``"<id>"`` matches any single segment."""
    return len(actual) == len(pattern) and all(
        a == p or p == "<id>" for a, p in zip(actual, pattern, strict=True)
    )


def _resolve_vm_fixture(method: str, path: str) -> str | None:
    clean = path.split("?")[0].rstrip("/")
    parts = [p for p in clean.split("/") if p]

    # POST /assets/search and POST /v4/integration/assets both list assets
    if method == "POST" and len(parts) >= 2 and tuple(parts[-2:]) in (
        ("assets", "search"),
        ("integration", "assets"),
    ):
        return "assets.json"

    # Strip the cloud prefix /v4/integration/...
    if len(parts) >= 3 and parts[0] == "v4" and parts[1] == "integration":
        parts = parts[2:]

    if not parts:
        return None

    # Cloud endpoint method-specific fixtures (after prefix-strip)
    if method == "POST" and tuple(parts) == ("scan",):
        return "scan_start.json"
    if method == "POST" and len(parts) == 4 and parts[0] == "scan" and parts[1] == "engine" and parts[3] == "configuration":
        return "scan_engine_update_config.json"
    if method == "DELETE" and len(parts) == 4 and parts[0] == "scan" and parts[1] == "engine" and parts[3] == "configuration":
        return "scan_engine_remove_config.json"

    key = tuple(parts)
    for pattern, fixture in _FIXTURE_RULES:
        if _fixture_match(key, pattern):
            return fixture
    return None


# ---------------------------------------------------------------------------
# InsightIDR fixture resolution
# ---------------------------------------------------------------------------


def _resolve_idr_fixture(method: str, path: str) -> str | None:
    """Map an InsightIDR API path to a fixture filename.

    Paths are full API paths, e.g. /idr/v2/investigations or /query/logs.
    """
    clean = path.split("?")[0].rstrip("/")
    parts = [p for p in clean.split("/") if p]

    if not parts:
        return None

    # /idr/v2/investigations[/{id}[/...]]
    if "investigations" in parts:
        idx = parts.index("investigations")
        tail = parts[idx + 1:]
        if not tail:
            # GET list or POST bulk_close
            if method == "POST":
                return "bulk_close.json"
            return "investigations.json"
        # /idr/v2/investigations/_search
        if method == "POST" and tail[0] == "_search":
            return "investigations.json"
        # /idr/v2/investigations/bulk_close
        if tail[0] == "bulk_close":
            return "bulk_close.json"
        # /idr/v2/investigations/{id}/alerts
        if len(tail) >= 2 and tail[1] == "alerts":
            return "investigation_alerts.json"
        # /idr/v2/investigations/{id}/rapid7-product-alerts
        if len(tail) >= 2 and tail[1] == "rapid7-product-alerts":
            return "investigation_alerts.json"
        # PATCH / PUT on investigation (assign, disposition, status, priority)
        if method in ("PATCH", "PUT"):
            return "investigation.json"
        return "investigation.json"

    # /idr/v1/comments
    if "comments" in parts:
        idx = parts.index("comments")
        if idx == len(parts) - 1:
            return "comments.json" if method == "GET" else "comment.json"
        return "comment.json"

    # /idr/v1/accounts/_search or /idr/v1/accounts/{rrn}
    if "accounts" in parts:
        idx = parts.index("accounts")
        if idx == len(parts) - 1 or parts[idx + 1] == "_search":
            return "idr_accounts.json"
        return "idr_account.json"

    # /idr/v1/users/_search or /idr/v1/users/{rrn}
    if "users" in parts:
        idx = parts.index("users")
        if idx == len(parts) - 1 or parts[idx + 1] == "_search":
            return "idr_users.json"
        return "idr_user.json"

    # /idr/v1/assets/_search or /idr/v1/assets/{rrn}
    if "assets" in parts:
        idx = parts.index("assets")
        if idx == len(parts) - 1 or parts[idx + 1] == "_search":
            return "idr_assets.json"
        return "idr_asset.json"

    # /idr/v1/rules or /idr/v1/rules/{rrn}  (real detection-rules path)
    if "rules" in parts and "detection-rules" not in parts:
        idx = parts.index("rules")
        if idx == len(parts) - 1:
            return "detection_rules.json"
        return "detection_rule.json"

    # /idr/v1/detection-rules (legacy path — kept for old fixture tests)
    if "detection-rules" in parts:
        idx = parts.index("detection-rules")
        if idx == len(parts) - 1 or parts[idx + 1] == "_search":
            return "detection_rules.json"
        return "detection_rule.json"

    # /idr/v2/iocs
    if "iocs" in parts:
        return "indicators.json"

    # /idr/v1/health-metrics
    if "health-metrics" in parts:
        return "health_metrics.json"

    # POST /query/logs
    if method == "POST" and len(parts) == 2 and parts[0] == "query" and parts[1] == "logs":
        return "log_search_results.json"

    # GET /management/logs
    if method == "GET" and len(parts) == 2 and parts[0] == "management" and parts[1] == "logs":
        return "logs.json"

    return None


# ---------------------------------------------------------------------------
# Automation (InsightConnect) fixture resolution
# ---------------------------------------------------------------------------


def _resolve_connect_fixture(method: str, path: str) -> str | None:
    clean = path.split("?")[0].rstrip("/")
    parts = [p for p in clean.split("/") if p]

    if len(parts) < 2 or parts[0] != "connect":
        return None

    # /connect/v1/jobs or /connect/v1/jobs/{job_id}
    if len(parts) >= 3 and parts[1] == "v1" and parts[2] == "jobs":
        return "connect_jobs.json" if len(parts) == 3 else "connect_job.json"

    # /connect/v2/workflows or /connect/v2/workflows/{workflow_id}
    if len(parts) >= 3 and parts[1] == "v2" and parts[2] == "workflows":
        return "connect_workflows.json" if len(parts) == 3 else "connect_workflow.json"

    return None


# ---------------------------------------------------------------------------
# Metasploit Pro fixture resolution
# ---------------------------------------------------------------------------


def _resolve_msp_fixture(method: str, path: str) -> str | None:
    """Map a Metasploit Pro API path to a fixture filename."""
    clean = path.split("?")[0].rstrip("/")
    parts = [p for p in clean.split("/") if p]

    if not parts:
        return None

    root = parts[0]

    if root == "workspaces":
        return "workspaces.json" if len(parts) == 1 else "workspace.json"

    if root == "sessions":
        return "sessions.json"

    if root == "looted_credentials":
        return "loot.json"

    if root == "tasks":
        return "msp_tasks.json"

    return None


# ---------------------------------------------------------------------------
# InsightVM clients
# ---------------------------------------------------------------------------


class InsightVMClient:
    """Async HTTP wrapper for the InsightVM REST API.

    Two topologies are supported via ``settings.insight_install``:

    * ``local`` (default) — on-prem console. Basic Auth, ``/api/3`` paths.
      Docs: https://help.rapid7.com/insightvm/en-us/api/index.html
    * ``cloud`` — Insight Platform managed. X-Api-Key, ``/vm`` base with
      ``/v4/integration/...`` paths (the "Cloud Integrations API"). The
      router paths include the ``/v4/integration/`` segment explicitly so
      routers can branch per-endpoint. Cloud paths are documented in the
      v4 OpenAPI spec at
      https://help.rapid7.com/insightvm/en-us/api/insightvm-api-v4.json
      and the user-facing reference at
      https://help.rapid7.com/insightvm/en-us/api/integrations.html.

    The local and cloud APIs use different endpoint paths AND different
    response shapes. Routers branch internally on ``insight_install``;
    endpoints without a cloud equivalent return ``501 Not Implemented``.
    A warning is emitted on first construction in cloud mode.
    """

    _CLOUD_WARNING_EMITTED = False
    _TIMEOUT_SECONDS = 60.0

    def _request_kwargs(self) -> dict[str, Any]:
        """Return the per-request auth/headers for the active install type."""
        if self._auth is not None:
            return {"auth": self._auth}
        if self._headers is not None:
            return {"headers": self._headers}
        return {}

    @staticmethod
    def _http_error_detail(response: httpx.Response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            return response.text
        if isinstance(payload, dict):
            for key in ("message", "localized_message", "detail", "error"):
                value = payload.get(key)
                if value:
                    return value
        return payload

    @staticmethod
    def _parse_json_response(response: httpx.Response) -> dict[str, Any]:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    def __init__(self, settings: Settings) -> None:
        if settings.insight_install == "cloud":
            self.base_url = f"https://{settings.vm_region}.api.insight.rapid7.com/vm"
            self._auth: tuple[str, str] | None = None
            self._headers: dict[str, str] | None = {
                "X-Api-Key": settings.vm_api_key,
                "Content-Type": "application/json",
            }
            self._verify = True
            if not InsightVMClient._CLOUD_WARNING_EMITTED:
                warnings.warn(
                    "InsightVM cloud mode is active. Some endpoints are not "
                    "available in the cloud API (asset_groups, remediation, "
                    "reports) and return 501. Mapped endpoints call the "
                    "v4 integrations API with different response shapes than "
                    "the on-prem v3 API.",
                    stacklevel=2,
                )
                InsightVMClient._CLOUD_WARNING_EMITTED = True
        else:
            self.base_url = f"{settings.console_url}/api/3"
            self._auth = (settings.username, settings.password)
            self._headers = None
            self._verify = settings.verify_ssl

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify, timeout=self._TIMEOUT_SECONDS) as client:
            try:
                r = await client.get(
                    f"{self.base_url}{path}", params=params, **self._request_kwargs()
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightVM cloud request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify, timeout=self._TIMEOUT_SECONDS) as client:
            try:
                r = await client.post(
                    f"{self.base_url}{path}", json=body or {}, **self._request_kwargs()
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightVM cloud request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)

    async def put(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify, timeout=self._TIMEOUT_SECONDS) as client:
            try:
                r = await client.put(
                    f"{self.base_url}{path}", json=body or {}, **self._request_kwargs()
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightVM cloud request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)

    async def delete(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify, timeout=self._TIMEOUT_SECONDS) as client:
            try:
                r = await client.request(
                    "DELETE",
                    f"{self.base_url}{path}",
                    json=body or {},
                    **self._request_kwargs(),
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightVM cloud request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)


class DemoInsightVMClient(InsightVMClient):
    """Returns fixture data — no live console required (``DEMO_MODE=true``)."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_vm_fixture("GET", path)
        return _load_fixture(fixture) if fixture else _EMPTY_PAGE.copy()

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_vm_fixture("POST", path)
        return _load_fixture(fixture) if fixture else _EMPTY_PAGE.copy()

    async def delete(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_vm_fixture("DELETE", path)
        return _load_fixture(fixture) if fixture else {}


def get_client(settings: Settings = Depends(get_settings)) -> InsightVMClient:
    """FastAPI dependency — InsightVM client, real or demo."""
    if settings.demo_mode:
        return DemoInsightVMClient(settings)
    return InsightVMClient(settings)


# ---------------------------------------------------------------------------
# InsightIDR clients
# ---------------------------------------------------------------------------


class InsightIDRClient:
    """Async HTTP wrapper for the Insight Platform API (InsightIDR v2).

    Uses ``X-Api-Key`` header auth against the Rapid7 cloud API.
    Region must be one of: us, us2, us3, eu, ca, au, ap.
    """

    _MAX_LOG_POLLS = 10
    _TIMEOUT_SECONDS = 60.0

    def __init__(self, settings: Settings) -> None:
        self.idr_base_url = f"https://{settings.idr_region}.api.insight.rapid7.com"
        self.logs_base_url = f"https://{settings.idr_region}.rest.logs.insight.rapid7.com"
        self._headers = {
            "X-Api-Key": settings.idr_api_key,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _http_error_detail(response: httpx.Response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            return response.text
        if isinstance(payload, dict):
            for key in ("message", "localized_message", "detail", "error"):
                value = payload.get(key)
                if value:
                    return value
        return payload

    @staticmethod
    def _parse_json_response(response: httpx.Response) -> dict[str, Any]:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        use_logs_api: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        base_url = self.logs_base_url if use_logs_api else self.idr_base_url
        effective_timeout = timeout if timeout is not None else self._TIMEOUT_SECONDS
        async with httpx.AsyncClient(timeout=effective_timeout) as client:
            try:
                r = await client.request(
                    method,
                    f"{base_url}{path}",
                    headers=self._headers,
                    params=params,
                    json=body or {},
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightIDR request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        use_logs_api: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return await self._request("GET", path, params=params, use_logs_api=use_logs_api, timeout=timeout)

    async def post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        use_logs_api: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return await self._request("POST", path, body=body, use_logs_api=use_logs_api, timeout=timeout)

    async def patch(
        self,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._request("PATCH", path, body=body)

    async def put(
        self,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._request("PUT", path, body=body)

    async def query_logs(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = await self.post("/query/logs", body=payload, use_logs_api=True)

        for _ in range(self._MAX_LOG_POLLS):
            if data.get("progress") is None:
                return data
            self_link = next(
                (link["href"] for link in data.get("links", []) if link.get("rel") == "Self"),
                None,
            )
            if not self_link:
                return data
            path = self_link.split(".rapid7.com", 1)[-1]
            data = await self.get(path, use_logs_api=True)
        return data


class DemoInsightIDRClient(InsightIDRClient):
    """Returns fixture data for InsightIDR (``DEMO_MODE=true``)."""

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        use_logs_api: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("GET", path)
        return _load_fixture(fixture) if fixture else {"data": [], "metadata": {"total_data": 0}}

    async def post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        use_logs_api: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("POST", path)
        return _load_fixture(fixture) if fixture else {"data": [], "metadata": {"total_data": 0}}

    async def patch(
        self,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("PATCH", path)
        return _load_fixture(fixture) if fixture else {}

    async def put(
        self,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("PUT", path)
        return _load_fixture(fixture) if fixture else {}


def get_idr_client(settings: Settings = Depends(get_settings)) -> InsightIDRClient:
    """FastAPI dependency — InsightIDR client, real or demo."""
    if settings.demo_mode:
        return DemoInsightIDRClient(settings)
    return InsightIDRClient(settings)


# ---------------------------------------------------------------------------
# Automation (InsightConnect) clients
# ---------------------------------------------------------------------------


class InsightConnectClient:
    """Async HTTP wrapper for Rapid7 Automation (InsightConnect) APIs."""

    _TIMEOUT_SECONDS = 60.0

    def __init__(self, settings: Settings) -> None:
        region = settings.connect_region or settings.idr_region
        api_key = settings.connect_api_key or settings.idr_api_key
        self.base_url = f"https://{region}.api.insight.rapid7.com"
        self._headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _http_error_detail(response: httpx.Response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            return response.text
        if isinstance(payload, dict):
            for key in ("message", "localized_message", "detail", "error"):
                value = payload.get(key)
                if value:
                    return value
        return payload

    @staticmethod
    def _parse_json_response(response: httpx.Response) -> dict[str, Any]:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._TIMEOUT_SECONDS) as client:
            try:
                r = await client.get(
                    f"{self.base_url}{path}",
                    headers=self._headers,
                    params=params,
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"InsightConnect request failed: {exc}",
                ) from exc
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail=self._http_error_detail(exc.response),
                ) from exc
            return self._parse_json_response(r)


class DemoInsightConnectClient(InsightConnectClient):
    """Returns fixture data for InsightConnect (``DEMO_MODE=true``)."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_connect_fixture("GET", path)
        if not fixture:
            return {"data": {}}
        return _load_fixture(fixture)


def get_connect_client(settings: Settings = Depends(get_settings)) -> InsightConnectClient:
    """FastAPI dependency — InsightConnect client, real or demo."""
    if settings.demo_mode:
        return DemoInsightConnectClient(settings)
    return InsightConnectClient(settings)


# ---------------------------------------------------------------------------
# Metasploit Pro clients
# ---------------------------------------------------------------------------


class MetasploitClient:
    """Async HTTP wrapper for the Metasploit Pro REST API (v1).

    Uses ``X-Metasploit-Token`` header auth. All operations are read-only —
    this client intentionally exposes no exploit execution or mutation methods.
    """

    def __init__(self, settings: Settings) -> None:
        self.base_url = f"{settings.msp_url}/api/v1"
        self._headers = {
            "X-Metasploit-Token": settings.msp_token,
            "Content-Type": "application/json",
        }
        self._verify = settings.msp_verify_ssl

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify) as client:
            r = await client.get(f"{self.base_url}{path}", headers=self._headers, params=params)
            r.raise_for_status()
            return r.json()


class DemoMetasploitClient(MetasploitClient):
    """Returns fixture data for Metasploit Pro (``DEMO_MODE=true``)."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_msp_fixture("GET", path)
        return _load_fixture(fixture) if fixture else {"data": []}


def get_msp_client(settings: Settings = Depends(get_settings)) -> MetasploitClient:
    """FastAPI dependency — Metasploit Pro client, real or demo."""
    if settings.demo_mode:
        return DemoMetasploitClient(settings)
    return MetasploitClient(settings)
