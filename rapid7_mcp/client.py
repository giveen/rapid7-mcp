"""Async HTTP clients for Rapid7 InsightVM, InsightIDR, and Metasploit Pro."""

import json
import warnings
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends

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


def _resolve_vm_fixture(method: str, path: str) -> str | None:
    """Map an InsightVM API path to a fixture filename."""
    clean = path.split("?")[0].rstrip("/")
    parts = [p for p in clean.split("/") if p]

    if method == "POST" and clean == "/assets/search":
        return "assets.json"

    if not parts:
        return None

    root = parts[0]

    if root == "sites":
        return "sites.json" if len(parts) == 1 else "site.json"

    if root == "asset_groups":
        return "asset_groups.json" if len(parts) == 1 else "asset_group.json"

    if root == "assets" and len(parts) == 3 and parts[2] == "vulnerabilities":
        return "asset_vulnerabilities.json"

    if root == "assets" and len(parts) == 3 and parts[2] == "tags":
        return "asset_tags.json"

    if root == "assets" and len(parts) == 2:
        return "asset.json"

    if root == "vulnerabilities":
        return "vulnerabilities.json" if len(parts) == 1 else "vulnerability.json"

    if root == "scans":
        return "scans.json" if len(parts) == 1 else "scan.json"

    if root == "remediation_projects":
        return "remediation_projects.json" if len(parts) == 1 else "remediation_project.json"

    if root == "reports":
        if len(parts) == 1:
            return "reports.json"
        if len(parts) == 3 and parts[2] == "generate":
            return "report_generate.json"
        return "report.json"

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

    # /idr/v2/investigations[/{id}]
    if "investigations" in parts:
        idx = parts.index("investigations")
        if idx == len(parts) - 1:
            return "investigations.json"
        # /idr/v2/investigations/_search
        if method == "POST" and parts[idx + 1] == "_search":
            return "investigations.json"
        # /idr/v2/investigations/{id}/alerts
        if idx + 2 < len(parts) and parts[idx + 2] == "alerts":
            return "investigation_alerts.json"
        return "investigation.json"

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
    * ``cloud`` — Insight Platform managed. X-Api-Key, ``/vm/v4/integration``
      paths (the "Cloud Integrations API"). The cloud API is JS-rendered
      only and has no publicly downloadable OpenAPI spec; the
      /vm/v4/integration segment is verified from community forum posts and
      the BlinkOps integration docs.
      Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html

    The local and cloud APIs use different endpoint paths AND different
    response shapes. In cloud mode the existing routers still call
    ``/api/3`` paths and most calls will fail until each router is rewired
    against a live-fetched cloud spec. A warning is emitted on first
    construction in cloud mode flagging this.

    Status: cloud rewiring is BLOCKED on spec access — the help.rapid7.com
    VM docs are not programmatically reachable. To finish the rewiring, an
    operator must export the OpenAPI spec from an authenticated console
    session (e.g. /api/3/html) or capture it via the JS-rendered
    integrations.html page and feed it back here.
    """

    _CLOUD_WARNING_EMITTED = False

    def _request_kwargs(self) -> dict[str, Any]:
        """Return the per-request auth/headers for the active install type."""
        if self._auth is not None:
            return {"auth": self._auth}
        if self._headers is not None:
            return {"headers": self._headers}
        return {}

    def __init__(self, settings: Settings) -> None:
        if settings.insight_install == "cloud":
            self.base_url = (
                f"https://{settings.vm_region}.api.insight.rapid7.com/vm/v4/integration"
            )
            self._auth: tuple[str, str] | None = None
            self._headers: dict[str, str] | None = {
                "X-Api-Key": settings.vm_api_key,
                "Content-Type": "application/json",
            }
            self._verify = True
            if not InsightVMClient._CLOUD_WARNING_EMITTED:
                warnings.warn(
                    "InsightVM cloud mode is active (base path "
                    "/vm/v4/integration). The existing routers still target the "
                    "on-prem /api/3 endpoints and most response shapes don't match "
                    "the Cloud Integrations API. Cloud calls will fail until each "
                    "router is rewired against a live-fetched cloud spec. See "
                    "https://help.rapid7.com/insightvm/en-us/api/integrations.html",
                    stacklevel=2,
                )
                InsightVMClient._CLOUD_WARNING_EMITTED = True
        else:
            self.base_url = f"{settings.console_url}/api/3"
            self._auth = (settings.username, settings.password)
            self._headers = None
            self._verify = settings.verify_ssl

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify) as client:
            r = await client.get(
                f"{self.base_url}{path}", params=params, **self._request_kwargs()
            )
            r.raise_for_status()
            return r.json()

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify) as client:
            r = await client.post(
                f"{self.base_url}{path}", json=body or {}, **self._request_kwargs()
            )
            r.raise_for_status()
            return r.json()

    async def put(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(verify=self._verify) as client:
            r = await client.put(
                f"{self.base_url}{path}", json=body or {}, **self._request_kwargs()
            )
            r.raise_for_status()
            return r.json()


class DemoInsightVMClient(InsightVMClient):
    """Returns fixture data — no live console required (``DEMO_MODE=true``)."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_vm_fixture("GET", path)
        return _load_fixture(fixture) if fixture else _EMPTY_PAGE.copy()

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_vm_fixture("POST", path)
        return _load_fixture(fixture) if fixture else _EMPTY_PAGE.copy()


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

    def __init__(self, settings: Settings) -> None:
        self.base_url = f"https://{settings.idr_region}.api.insight.rapid7.com"
        self._headers = {
            "X-Api-Key": settings.idr_api_key,
            "Content-Type": "application/json",
        }

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.base_url}{path}", headers=self._headers, params=params)
            r.raise_for_status()
            return r.json()

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self.base_url}{path}", headers=self._headers, json=body or {})
            r.raise_for_status()
            return r.json()


class DemoInsightIDRClient(InsightIDRClient):
    """Returns fixture data for InsightIDR (``DEMO_MODE=true``)."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("GET", path)
        return _load_fixture(fixture) if fixture else {"data": [], "metadata": {"total_data": 0}}

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = _resolve_idr_fixture("POST", path)
        return _load_fixture(fixture) if fixture else {"data": [], "metadata": {"total_data": 0}}


def get_idr_client(settings: Settings = Depends(get_settings)) -> InsightIDRClient:
    """FastAPI dependency — InsightIDR client, real or demo."""
    if settings.demo_mode:
        return DemoInsightIDRClient(settings)
    return InsightIDRClient(settings)


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
