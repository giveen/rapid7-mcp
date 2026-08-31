"""Vulnerabilities router — InsightVM vulnerability library."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import Vulnerability, VulnerabilityList

router = APIRouter()


@router.get(
    "",
    operation_id="list_vulnerabilities",
    summary="List vulnerabilities",
    description=(
        "Returns vulnerabilities from the InsightVM library. "
        "Filter by severity (Critical, Severe, Moderate, Low, Informational) to narrow results. "
        "Results include CVSS scores, CVE IDs, and exploit availability."
    ),
)
async def list_vulnerabilities(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    severity: str | None = Query(
        None,
        description="Filter by severity: Critical, Severe, Moderate, Low, Informational",
    ),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        query = f"severity = '{severity.lower()}'" if severity else None
        body: dict[str, str] = {"vulnerability": query} if query else {}
        return await client.post("/v4/integration/vulnerabilities", body=body)
    params: dict = {"page": page, "size": size}
    if severity:
        params["severity"] = severity
    data = await client.get("/vulnerabilities", params=params)
    return VulnerabilityList(**data)


@router.get(
    "/{vuln_id}",
    operation_id="get_vulnerability",
    summary="Get vulnerability details",
    description=(
        "Returns full details for a vulnerability including title, description, CVSS v2/v3 scores, "
        "CVE IDs, affected software categories, exploit count, and available remediations."
    ),
)
async def get_vulnerability(
    vuln_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        data = await client.post(
            "/v4/integration/vulnerabilities",
            body={"vulnerability": f"id = '{vuln_id}'"},
        )
        resources = data.get("data") or data.get("resources", [])
        if not resources:
            raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found")
        return resources[0]
    data = await client.get(f"/vulnerabilities/{vuln_id}")
    return Vulnerability(**data)
