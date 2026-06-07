"""Scans router — InsightVM scan management."""

from typing import Any

from fastapi import APIRouter, Depends, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import Scan, ScanList

router = APIRouter()


@router.get(
    "",
    operation_id="list_scans",
    summary="List scans",
    description=(
        "Returns recent scans across all sites. "
        "Includes scan status (running, finished, stopped, paused), "
        "asset counts, vulnerability findings, and duration. "
        "In cloud mode the response shape follows the v4 Integrations API."
    ),
)
async def list_scans(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    active: bool | None = Query(None, description="Filter to only active (running) scans"),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.get("/v4/integration/scan", params={"page": page, "size": size})
    params: dict = {"page": page, "size": size}
    if active is not None:
        params["active"] = active
    data = await client.get("/scans", params=params)
    return ScanList(**data)


@router.get(
    "/{scan_id}",
    operation_id="get_scan",
    summary="Get a scan by ID",
    description="Returns details for a single scan including status, timing, and vulnerability summary.",
)
async def get_scan(
    scan_id: int,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.get(f"/v4/integration/scan/{scan_id}")
    data = await client.get(f"/scans/{scan_id}")
    return Scan(**data)
