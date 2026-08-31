"""Scans router — InsightVM scan management."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import (
    Scan,
    ScanEngineConfigurationRemoveRequest,
    ScanEngineConfigurationUpdateRequest,
    ScanList,
    ScanStartRequest,
)

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


@router.post(
    "",
    operation_id="start_scan",
    summary="Start an InsightVM cloud scan",
    description=(
        "Starts a new scan in InsightVM cloud mode using the v4 integrations API. "
        "This tool is cloud-only."
    ),
)
async def start_scan(
    body: ScanStartRequest,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="start_scan is cloud-only and not exposed through the on-prem API routes.",
        )
    return await client.post("/v4/integration/scan", body=body.model_dump(exclude_none=True))


@router.post(
    "/{scan_id}/stop",
    operation_id="stop_scan",
    summary="Stop an active InsightVM cloud scan",
    description="Stops an in-progress cloud scan by its scan ID.",
)
async def stop_scan(
    scan_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="stop_scan is cloud-only and not exposed through the on-prem API routes.",
        )
    return await client.post(f"/v4/integration/scan/{scan_id}/stop")


@router.get(
    "/engine",
    operation_id="list_scan_engines",
    summary="List InsightVM cloud scan engines",
    description="Returns registered cloud scan engines and their health status.",
)
async def list_scan_engines(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="list_scan_engines is cloud-only and not exposed through on-prem API routes.",
        )
    return await client.get("/v4/integration/scan/engine", params={"page": page, "size": size})


@router.get(
    "/engine/{engine_id}",
    operation_id="get_scan_engine",
    summary="Get one InsightVM cloud scan engine",
    description="Returns details for a specific cloud scan engine.",
)
async def get_scan_engine(
    engine_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_scan_engine is cloud-only and not exposed through on-prem API routes.",
        )
    return await client.get(f"/v4/integration/scan/engine/{engine_id}")


@router.post(
    "/engine/{engine_id}/configuration",
    operation_id="update_scan_engine_configuration",
    summary="Update cloud scan engine configuration properties",
    description="Sets scan-engine configuration properties for the given engine ID.",
)
async def update_scan_engine_configuration(
    engine_id: str,
    body: ScanEngineConfigurationUpdateRequest,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="update_scan_engine_configuration is cloud-only.",
        )
    return await client.post(
        f"/v4/integration/scan/engine/{engine_id}/configuration",
        body=body.model_dump(exclude_none=True),
    )


@router.delete(
    "/engine/{engine_id}/configuration",
    operation_id="remove_scan_engine_configuration",
    summary="Remove cloud scan engine configuration properties",
    description="Removes one or more scan-engine configuration properties for the given engine.",
)
async def remove_scan_engine_configuration(
    engine_id: str,
    body: ScanEngineConfigurationRemoveRequest,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="remove_scan_engine_configuration is cloud-only.",
        )
    return await client.delete(
        f"/v4/integration/scan/engine/{engine_id}/configuration",
        body=body.model_dump(exclude_none=True),
    )


@router.get(
    "/{scan_id}",
    operation_id="get_scan",
    summary="Get a scan by ID",
    description="Returns details for a single scan including status, timing, and vulnerability summary.",
)
async def get_scan(
    scan_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.get(f"/v4/integration/scan/{scan_id}")
    data = await client.get(f"/scans/{scan_id}")
    return Scan(**data)
