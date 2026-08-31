"""InsightIDR router — cloud SIEM investigations and log search."""

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.models import (
    AddCommentRequest,
    AssignInvestigationRequest,
    BulkCloseRequest,
    BulkCloseResponse,
    HealthMetricList,
    IdrComment,
    IdrCommentList,
    IndicatorList,
    Investigation,
    InvestigationAlertList,
    InvestigationList,
    InvestigationSearchRequest,
    LogInfoList,
    LogSearchRequest,
    LogSearchResults,
)

router = APIRouter()


@router.get(
    "/investigations",
    response_model=InvestigationList,
    operation_id="list_investigations",
    summary="List InsightIDR investigations",
    description=(
        "Returns InsightIDR investigations (security incidents). Each investigation aggregates "
        "related alerts with an assigned priority, status, and optional assignee. "
        "Filter by status to focus on open incidents requiring attention. "
        "Use get_investigation for the full alert timeline."
    ),
)
async def list_investigations(
    status: str = Query("OPEN", description="Filter by status: OPEN, CLOSED, INVESTIGATING"),
    priority: str | None = Query(
        None, description="Filter by priority: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    page_token: str | None = Query(None, description="Pagination cursor from previous response"),
    size: int = Query(20, ge=1, le=100),
    client: InsightIDRClient = Depends(get_idr_client),
) -> InvestigationList:
    params: dict = {"statuses": status, "size": size}
    if priority:
        params["priorities"] = priority
    if page_token:
        params["index"] = page_token
    data = await client.get("/idr/v2/investigations", params=params)
    return InvestigationList(**data)


@router.get(
    "/investigations/{investigation_id}",
    response_model=Investigation,
    operation_id="get_investigation",
    summary="Get an investigation by ID",
    description=(
        "Returns full details for a single InsightIDR investigation including all associated alerts, "
        "timeline, assignee, priority, and disposition. Use this to understand the full context "
        "of an active security incident."
    ),
)
async def get_investigation(
    investigation_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation rrn from list_investigations for live InsightIDR lookups.",
        )
    data = await client.get(f"/idr/v2/investigations/{investigation_id}")
    return Investigation(**data)


@router.get(
    "/investigations/{investigation_id}/alerts",
    response_model=InvestigationAlertList,
    operation_id="list_investigation_alerts",
    summary="List alerts associated with an investigation",
    description=(
        "Returns the alerts that triggered or are associated with a given InsightIDR "
        "investigation. Each alert includes its source, type, first/latest event time, "
        "and the detection rule that produced it. Use this to drill into the timeline "
        "of an active incident."
    ),
)
async def list_investigation_alerts(
    investigation_id: str,
    page_token: str | None = Query(None, description="Pagination cursor from previous response"),
    size: int = Query(20, ge=1, le=100),
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> InvestigationAlertList:
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation rrn from list_investigations for live InsightIDR lookups.",
        )
    params: dict = {"size": size}
    if page_token:
        params["index"] = page_token
    data = await client.get(
        f"/idr/v2/investigations/{investigation_id}/alerts", params=params
    )
    return InvestigationAlertList(**data)


@router.post(
    "/investigations/_search",
    response_model=InvestigationList,
    operation_id="search_investigations",
    summary="Search investigations with structured criteria",
    description=(
        "Free-form search of InsightIDR investigations. Supports multiple criteria "
        "(field, operator EQUALS|CONTAINS|IN, value), sort directives, and a time "
        "window. Use this for hunting by title, source, status, or custom fields. "
        "Returns the same page shape as list_investigations."
    ),
)
async def search_investigations(
    body: InvestigationSearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> InvestigationList:
    data = await client.post("/idr/v2/investigations/_search", body=body.model_dump(exclude_none=True))
    return InvestigationList(**data)


@router.patch(
    "/investigations/{investigation_id}",
    response_model=Investigation,
    operation_id="assign_investigation",
    summary="Assign an investigation to an analyst",
    description=(
        "Assigns an InsightIDR investigation to an analyst by email address. "
        "Use list_investigations to find open investigations, then assign to the "
        "appropriate team member for triage. Pass the full investigation RRN as the ID."
    ),
)
async def assign_investigation(
    investigation_id: str,
    body: AssignInvestigationRequest,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    data = await client.patch(
        f"/idr/v2/investigations/{investigation_id}",
        body={"assignee": {"email": body.email}},
    )
    return Investigation(**data)


@router.put(
    "/investigations/{investigation_id}/disposition/{disposition}",
    response_model=Investigation,
    operation_id="set_investigation_disposition",
    summary="Set the disposition of an investigation",
    description=(
        "Sets the disposition of an InsightIDR investigation. "
        "Disposition represents the analyst's conclusion about the nature of the incident. "
        "Valid values: BENIGN (false positive / expected behavior), "
        "MALICIOUS (confirmed threat), NOT_APPLICABLE (out of scope), UNDECIDED (still reviewing). "
        "Pass the full investigation RRN as the ID."
    ),
)
async def set_investigation_disposition(
    investigation_id: str,
    disposition: str,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    disposition = disposition.upper()
    valid = {"BENIGN", "MALICIOUS", "NOT_APPLICABLE", "UNDECIDED"}
    if disposition not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid disposition '{disposition}'. Must be one of: {', '.join(sorted(valid))}",
        )
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    data = await client.patch(
        f"/idr/v2/investigations/{investigation_id}",
        body={"disposition": disposition},
    )
    return Investigation(**data)


@router.put(
    "/investigations/{investigation_id}/status/{status}",
    response_model=Investigation,
    operation_id="set_investigation_status",
    summary="Set the status of an investigation",
    description=(
        "Updates the workflow status of an InsightIDR investigation. "
        "Valid values: OPEN (newly created, needs triage), "
        "INVESTIGATING (actively being worked), CLOSED (resolved). "
        "Closing an investigation should be done after setting disposition. "
        "Pass the full investigation RRN as the ID."
    ),
)
async def set_investigation_status(
    investigation_id: str,
    status: str,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    status = status.upper()
    valid = {"OPEN", "INVESTIGATING", "CLOSED"}
    if status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid))}",
        )
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    data = await client.put(f"/idr/v2/investigations/{investigation_id}/status/{status}")
    return Investigation(**data)


@router.put(
    "/investigations/{investigation_id}/priority/{priority}",
    response_model=Investigation,
    operation_id="set_investigation_priority",
    summary="Set the priority of an investigation",
    description=(
        "Updates the priority of an InsightIDR investigation. "
        "Valid values: CRITICAL, HIGH, MEDIUM, LOW. "
        "Use this to escalate or de-escalate an investigation based on new findings. "
        "Pass the full investigation RRN as the ID."
    ),
)
async def set_investigation_priority(
    investigation_id: str,
    priority: str,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    priority = priority.upper()
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    if priority not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid priority '{priority}'. Must be one of: {', '.join(sorted(valid))}",
        )
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    data = await client.put(f"/idr/v2/investigations/{investigation_id}/priority/{priority}")
    return Investigation(**data)


@router.post(
    "/investigations/bulk_close",
    response_model=BulkCloseResponse,
    operation_id="bulk_close_investigations",
    summary="Bulk close InsightIDR investigations",
    description=(
        "Closes multiple InsightIDR investigations in a single operation. "
        "Optionally filter by alert_type, source, time window (from/to as ISO-8601), "
        "and set a disposition for all closed investigations. "
        "max_investigations_to_close caps the operation (default 100, max 10 000). "
        "Returns the number of investigations actually closed. "
        "Use list_investigations first to preview what will be affected."
    ),
)
async def bulk_close_investigations(
    body: BulkCloseRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> BulkCloseResponse:
    payload = body.model_dump(exclude_none=True, by_alias=True)
    data = await client.post("/idr/v2/investigations/bulk_close", body=payload)
    return BulkCloseResponse(**data)


@router.post(
    "/investigations/{investigation_id}/comments",
    response_model=IdrComment,
    operation_id="add_investigation_comment",
    summary="Add a comment to an investigation",
    description=(
        "Appends a Markdown comment to an InsightIDR investigation. "
        "Use this to document analyst findings, triage decisions, and remediation steps "
        "directly on the investigation record. "
        "Visibility can be 'public' (all org members) or 'private' (comment author only). "
        "Pass the full investigation RRN as the ID."
    ),
)
async def add_investigation_comment(
    investigation_id: str,
    body: AddCommentRequest,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrComment:
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    payload = {
        "body": body.body,
        "target": investigation_id,
        "visibility": body.visibility.upper(),
    }
    data = await client.post("/idr/v1/comments", body=payload)
    return IdrComment(**data)


@router.get(
    "/investigations/{investigation_id}/comments",
    response_model=IdrCommentList,
    operation_id="list_investigation_comments",
    summary="List comments on an investigation",
    description=(
        "Returns all analyst comments attached to an InsightIDR investigation. "
        "Comments contain triage notes, findings, and remediation context added during the "
        "investigation lifecycle. Pass the full investigation RRN as the ID."
    ),
)
async def list_investigation_comments(
    investigation_id: str,
    settings: Settings = Depends(get_settings),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrCommentList:
    if not settings.demo_mode and not investigation_id.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full investigation RRN from list_investigations.",
        )
    data = await client.get(
        "/idr/v1/comments",
        params={"target": investigation_id},
    )
    return IdrCommentList(**data)


@router.post(
    "/logs",
    response_model=LogSearchResults,
    operation_id="query_logs",
    summary="Search logs with LEQL",
    description=(
        "Execute a LEQL (Log Entry Query Language) query against InsightIDR log sets. "
        "Use this to hunt for indicators of compromise — search for specific IPs, file hashes, "
        "domain names, or user activity across firewall, proxy, DNS, and endpoint logs. "
        "Example LEQL: 'where(destination_ip = \"1.2.3.4\")'. "
        "Time range is specified as Unix epoch milliseconds."
    ),
)
async def query_logs(
    body: LogSearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> LogSearchResults:
    during: dict = {}
    if body.time_range:
        during["time_range"] = body.time_range
    else:
        if body.from_time is not None:
            during["from"] = body.from_time
        if body.to_time is not None:
            during["to"] = body.to_time
    payload: dict = {"leql": {"statement": body.query, "during": during}}
    if body.logs:
        payload["logs"] = body.logs
    data = await client.query_logs(payload)
    return LogSearchResults(**data)


@router.get(
    "/logs",
    response_model=LogInfoList,
    operation_id="list_logs",
    summary="List available InsightIDR logs",
    description=(
        "Enumerates every log configured in the InsightIDR tenant, returning each log's "
        "id (UUID), name, source type (syslog | token | internal), and retention period. "
        "The returned ``id`` values are the keys required by query_logs and saved-query "
        "endpoints. Use this to discover which log sets are available before hunting."
    ),
)
async def list_logs(
    client: InsightIDRClient = Depends(get_idr_client),
) -> LogInfoList:
    data = await client.get("/management/logs", use_logs_api=True)
    return LogInfoList(**data)


@router.get(
    "/iocs",
    response_model=IndicatorList,
    operation_id="list_indicators",
    summary="List threat intelligence indicators (IOCs)",
    description=(
        "Returns active Indicators of Compromise (IOCs) being tracked in InsightIDR's threat "
        "intelligence feed. Indicators include malicious IPs, domains, file hashes, and URLs "
        "associated with known threat actors or malware families. "
        "Use this to check whether an IP or domain seen in logs is a known bad actor."
    ),
)
async def list_indicators(
    indicator_type: str | None = Query(
        None,
        description="Filter by type: IP_ADDRESS, DOMAIN, URL, FILE_HASH",
    ),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IndicatorList:
    params: dict = {}
    if indicator_type:
        params["type"] = indicator_type
    try:
        data = await client.get("/idr/v2/iocs", params=params)
        return IndicatorList(**data)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(
                status_code=501,
                detail=(
                    "The tenant-accessible InsightIDR REST API does not expose an IOC feed endpoint "
                    "for this account/region."
                ),
            ) from exc
        raise


@router.get(
    "/health_metrics",
    response_model=HealthMetricList,
    operation_id="get_health_metrics",
    summary="Get InsightIDR health and usage metrics",
    description=(
        "Returns platform health metrics for the InsightIDR tenant — request counts, "
        "error rates, and resource utilisation. Useful as a connectivity / quota check "
        "and for capacity planning. Optional resource-type and org-id filters narrow "
        "the result set."
    ),
)
async def get_health_metrics(
    index: int | None = Query(None, ge=0, description="0-based page index"),
    size: int | None = Query(None, ge=1, le=100, description="Page size"),
    resource_types: str | None = Query(
        None, description="Comma-separated resource types to filter by"
    ),
    org_id: str | None = Query(
        None, description="Organization ID; defaults to the caller's home org"
    ),
    client: InsightIDRClient = Depends(get_idr_client),
) -> HealthMetricList:
    params: dict = {}
    if index is not None:
        params["index"] = index
    if size is not None:
        params["size"] = size
    if resource_types:
        params["resourceTypes"] = resource_types
    if org_id:
        params["orgId"] = org_id
    data = await client.get("/idr/v1/health-metrics", params=params)
    return HealthMetricList(**data)
