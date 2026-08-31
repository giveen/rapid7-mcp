"""Automation (InsightConnect) router — jobs and workflows."""

from fastapi import APIRouter, Depends, Query

from rapid7_mcp.client import InsightConnectClient, get_connect_client
from rapid7_mcp.models import (
    ConnectJobDetail,
    ConnectJobList,
    ConnectWorkflowDetail,
    ConnectWorkflowList,
)

router = APIRouter()


@router.get(
    "/jobs",
    response_model=ConnectJobList,
    operation_id="list_connect_jobs",
    summary="List Automation jobs",
    description=(
        "Returns Automation (InsightConnect) jobs from /connect/v1/jobs. "
        "Jobs are workflow execution instances with status, duration, step error counts, "
        "and captured inputs/outputs."
    ),
)
async def list_connect_jobs(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    client: InsightConnectClient = Depends(get_connect_client),
) -> ConnectJobList:
    data = await client.get("/connect/v1/jobs", params={"limit": limit, "offset": offset})
    return ConnectJobList(**data)


@router.get(
    "/jobs/{job_id}",
    response_model=ConnectJobDetail,
    operation_id="get_connect_job",
    summary="Get one Automation job",
    description=(
        "Returns full details for one Automation (InsightConnect) job from "
        "/connect/v1/jobs/{job_id}, including trigger inputs and step outputs."
    ),
)
async def get_connect_job(
    job_id: str,
    client: InsightConnectClient = Depends(get_connect_client),
) -> ConnectJobDetail:
    data = await client.get(f"/connect/v1/jobs/{job_id}")
    return ConnectJobDetail(**data)


@router.get(
    "/workflows",
    response_model=ConnectWorkflowList,
    operation_id="list_connect_workflows",
    summary="List Automation workflows",
    description=(
        "Returns Automation (InsightConnect) workflows from /connect/v2/workflows. "
        "Includes state (active/inactive), published/unpublished versions, and metadata."
    ),
)
async def list_connect_workflows(
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    client: InsightConnectClient = Depends(get_connect_client),
) -> ConnectWorkflowList:
    data = await client.get("/connect/v2/workflows", params={"limit": limit, "offset": offset})
    return ConnectWorkflowList(**data)


@router.get(
    "/workflows/{workflow_id}",
    response_model=ConnectWorkflowDetail,
    operation_id="get_connect_workflow",
    summary="Get one Automation workflow",
    description=(
        "Returns one Automation (InsightConnect) workflow from "
        "/connect/v2/workflows/{workflow_id}, including published/unpublished version metadata."
    ),
)
async def get_connect_workflow(
    workflow_id: str,
    client: InsightConnectClient = Depends(get_connect_client),
) -> ConnectWorkflowDetail:
    data = await client.get(f"/connect/v2/workflows/{workflow_id}")
    return ConnectWorkflowDetail(**data)
