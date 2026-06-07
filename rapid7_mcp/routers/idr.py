"""InsightIDR router — cloud SIEM investigations and log search."""

from fastapi import APIRouter, Depends, Query

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.models import (
    HealthMetricList,
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
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
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
    client: InsightIDRClient = Depends(get_idr_client),
) -> InvestigationAlertList:
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
    data = await client.post("/query/logs", body=payload)

    for _ in range(10):
        if data.get("progress") is None:
            return LogSearchResults(**data)
        self_link = next(
            (link["href"] for link in data.get("links", []) if link.get("rel") == "Self"),
            None,
        )
        if not self_link:
            return LogSearchResults(**data)
        path = self_link.split(".rapid7.com", 1)[-1]
        data = await client.get(path)
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
    data = await client.get("/management/logs")
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
    data = await client.get("/idr/v2/iocs", params=params)
    return IndicatorList(**data)


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
