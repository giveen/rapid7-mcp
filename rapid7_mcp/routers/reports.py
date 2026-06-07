"""Reports router — InsightVM report management."""

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import Report, ReportGenerateResponse, ReportList

router = APIRouter()


@router.get(
    "",
    response_model=ReportList,
    operation_id="list_reports",
    summary="List reports",
    description=(
        "Returns all configured InsightVM reports. Reports can be executive summaries, "
        "PCI compliance exports, vulnerability detail exports, and more. "
        "Use get_report or execute_report to retrieve or generate a specific report."
    ),
)
async def list_reports(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> ReportList:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="list_reports is not available in the InsightVM cloud API; "
            "the v4 Integrations API has no reports equivalent.",
        )
    data = await client.get("/reports", params={"page": page, "size": size})
    return ReportList(**data)


@router.get(
    "/{report_id}",
    response_model=Report,
    operation_id="get_report",
    summary="Get a report by ID",
    description="Returns configuration and status for a single report.",
)
async def get_report(
    report_id: int,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> Report:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="get_report is not available in the InsightVM cloud API.",
        )
    data = await client.get(f"/reports/{report_id}")
    return Report(**data)


@router.post(
    "/{report_id}/generate",
    response_model=ReportGenerateResponse,
    operation_id="execute_report",
    summary="Generate a report",
    description=(
        "Triggers on-demand generation of an InsightVM report. "
        "Returns the report instance ID and a URI where the output can be downloaded. "
        "Supported formats include PDF, HTML, XML, and CSV depending on the report template."
    ),
)
async def execute_report(
    report_id: int,
    settings: Settings = Depends(get_settings),
    client: InsightVMClient = Depends(get_client),
) -> ReportGenerateResponse:
    if settings.insight_install == "cloud":
        raise HTTPException(
            status_code=501,
            detail="execute_report is not available in the InsightVM cloud API.",
        )
    data = await client.post(f"/reports/{report_id}/generate")
    return ReportGenerateResponse(**data)
