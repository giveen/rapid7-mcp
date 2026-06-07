"""Sites router — InsightVM scan sites."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import Site, SiteList

router = APIRouter()


@router.get(
    "",
    operation_id="list_sites",
    summary="List all sites",
    description=(
        "Returns all InsightVM scan sites with asset counts, risk scores, and last scan times. "
        "Sites are the primary unit of organization for assets and scans. "
        "In cloud mode the response shape follows the v4 Integrations API."
    ),
)
async def list_sites(
    page: int = Query(0, ge=0, description="Page number (0-indexed)"),
    size: int = Query(10, ge=1, le=100, description="Number of results per page"),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install == "cloud":
        return await client.post(
            "/v4/integration/sites", body={"page": page, "size": size}
        )
    data = await client.get("/sites", params={"page": page, "size": size})
    return SiteList(**data)


@router.get(
    "/{site_id}",
    response_model=Site,
    operation_id="get_site",
    summary="Get a site by ID",
    description="Returns details for a single InsightVM site including asset count and risk score.",
)
async def get_site(
    site_id: int,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Site:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_site is not available in the InsightVM cloud API; use list_sites.",
        )
    data = await client.get(f"/sites/{site_id}")
    return Site(**data)
