"""InsightVM cloud health router (v4 Integrations API)."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import VmHealth

router = APIRouter()


@router.get(
    "/health",
    response_model=VmHealth,
    operation_id="get_vm_health",
    summary="Get InsightVM cloud health status",
    description=(
        "Returns the overall health of the InsightVM cloud service as reported by "
        "the v4 Integrations API's GET /admin/health endpoint. Cloud-only."
    ),
)
async def get_vm_health(
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Any:
    if settings.insight_install != "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_vm_health is a cloud-only tool. The on-prem console does "
            "not expose the v4 /admin/health endpoint via this MCP server.",
        )
    return await client.get("/admin/health")
