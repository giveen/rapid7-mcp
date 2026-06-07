"""Assets router — InsightVM managed assets."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import (
    Asset,
    AssetList,
    AssetSearchRequest,
    AssetTagList,
    AssetVulnerabilityList,
)

router = APIRouter()


@router.get(
    "/{asset_id}",
    operation_id="get_asset",
    summary="Get an asset by ID",
    description=(
        "Returns full details for a single asset including IP, hostname, operating system, "
        "vulnerability counts by severity, and risk score. In cloud mode the response "
        "shape follows the v4 Integrations API (AssetSummary)."
    ),
)
async def get_asset(
    asset_id: int,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.get(f"/v4/integration/assets/{asset_id}")
    data = await client.get(f"/assets/{asset_id}")
    return Asset(**data)


@router.post(
    "/search",
    operation_id="search_assets",
    summary="Search assets by filter criteria",
    description=(
        "Search for assets using field filters. "
        "Supported fields: ip-address, host-name, os-family, site-id, tag. "
        "Operators: is, is-not, contains, starts-with, ends-with, like. "
        "Example: filter by IP range or hostname pattern. "
        "In cloud mode the search is forwarded to POST /v4/integration/assets."
    ),
)
async def search_assets(
    body: AssetSearchRequest,
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.post(
            "/v4/integration/assets", body={"asset": body.model_dump_json()}
        )
    data = await client.post(
        f"/assets/search?page={page}&size={size}",
        body=body.model_dump(),
    )
    return AssetList(**data)


@router.get(
    "/{asset_id}/vulnerabilities",
    response_model=AssetVulnerabilityList,
    operation_id="get_asset_vulnerabilities",
    summary="List vulnerabilities for an asset",
    description=(
        "Returns all vulnerabilities found on a specific asset, with status and instance counts. "
        "Use the vulnerability ID from results with get_vulnerability for full details."
    ),
)
async def get_asset_vulnerabilities(
    asset_id: int,
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> AssetVulnerabilityList:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_asset_vulnerabilities is not available in the InsightVM cloud API.",
        )
    data = await client.get(
        f"/assets/{asset_id}/vulnerabilities",
        params={"page": page, "size": size},
    )
    return AssetVulnerabilityList(**data)


@router.get(
    "/{asset_id}/tags",
    response_model=AssetTagList,
    operation_id="get_asset_tags",
    summary="Get tags for an asset",
    description=(
        "Returns all tags assigned to an asset. Tags carry contextual metadata like owner, "
        "criticality, compliance scope (e.g. PCI, HIPAA), and environment (production, staging). "
        "Use this to understand business context before prioritizing remediation."
    ),
)
async def get_asset_tags(
    asset_id: int,
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> AssetTagList:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_asset_tags is not available in the InsightVM cloud API.",
        )
    data = await client.get(
        f"/assets/{asset_id}/tags",
        params={"page": page, "size": size},
    )
    return AssetTagList(**data)
