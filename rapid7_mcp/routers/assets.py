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
    CloudAssetList,
    CloudAssetSearchRequest,
)

router = APIRouter()


def _escape_cloud_literal(value: str) -> str:
    return value.replace("'", "\\'")


def _to_cloud_query(criteria: AssetSearchRequest) -> str:
    if criteria.cloud_query:
        return criteria.cloud_query

    if not criteria.filters:
        return ""

    field_map = {
        "host-name": "asset.host_name",
        "os-family": "asset.os_family",
        # The cloud query catalog does not support asset.ip/site-id/tag directly.
    }
    op_map = {"is": "=", "is-not": "!="}

    expressions: list[str] = []
    unsupported: list[str] = []
    for item in criteria.filters:
        mapped_field = field_map.get(item.field)
        mapped_op = op_map.get(item.operator)
        if mapped_field is None or mapped_op is None:
            unsupported.append(f"{item.field}:{item.operator}")
            continue
        expressions.append(f"{mapped_field} {mapped_op} '{_escape_cloud_literal(item.value)}'")

    if not expressions:
        details = ", ".join(sorted(set(unsupported)))
        raise HTTPException(
            status_code=400,
            detail=(
                "Cloud asset search does not support the provided legacy filters. "
                f"Unsupported filters: {details}. Use cloud_query with a v4 expression."
            ),
        )

    joiner = " && " if criteria.match.lower() == "all" else " || "
    return joiner.join(expressions)


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
    asset_id: str,
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
        cloud_query = _to_cloud_query(body)
        cloud_body = {"asset": cloud_query} if cloud_query else {}
        return await client.post("/v4/integration/assets", body=cloud_body)
    data = await client.post(
        f"/assets/search?page={page}&size={size}",
        body=body.model_dump(),
    )
    return AssetList(**data)


@router.post(
    "/cloud/search",
    response_model=CloudAssetList,
    operation_id="search_integration_assets",
    summary="Search InsightVM assets via Cloud Integration API (v4)",
    description=(
        "Search and filter assets using the InsightVM v4 Cloud Integration API "
        "(POST /vm/v4/integration/assets — searchIntegrationAssets). "
        "Returns the full cloud asset schema: vulnerability counts by severity, "
        "risk score, OS details, tags, unique identifiers (R7 Agent, AD, CSPRODUCT), "
        "credential assessment results, and last-scan timestamps. "
        "Use the LEQL ``asset`` filter to narrow results. Examples:\n"
        "  - All Windows assets: ``asset.os_family = 'Windows'``\n"
        "  - High-risk assets: ``asset.risk_score > 50000``\n"
        "  - Hostname contains 'prod': ``asset.host_name contains 'prod'``\n"
        "  - Combined: ``asset.os_family = 'Linux' && asset.risk_score > 10000``\n"
        "Paginate with the ``cursor`` token from metadata.cursor. "
        "Sort by risk-score (DESC) to see the most critical assets first. "
        "This tool is only available when R7_INSIGHT_INSTALL=cloud."
    ),
)
async def search_integration_assets(
    body: CloudAssetSearchRequest,
    cursor: str | None = Query(None, description="Cursor token from a previous response for next-page navigation"),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> CloudAssetList:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail=(
                "search_integration_assets requires R7_INSIGHT_INSTALL=cloud. "
                "For on-prem consoles use search_assets instead."
            ),
        )
    cloud_body: dict[str, Any] = {"size": body.size}
    if body.asset:
        cloud_body["asset"] = body.asset
    if body.sort:
        cloud_body["sort"] = [s.model_dump() for s in body.sort]
    if cursor:
        cloud_body["cursor"] = cursor
    data = await client.post("/v4/integration/assets", body=cloud_body)
    return CloudAssetList(**data)


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
