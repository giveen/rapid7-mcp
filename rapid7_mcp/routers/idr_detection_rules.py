"""InsightIDR detection rules router — read detection rule configurations.

The real endpoint is /idr/v1/rules (not /idr/v1/detection-rules).
Pagination uses a base64 cursor in the `position` field of the response.
"""

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.models import IdrDetectionRule, IdrDetectionRuleList

router = APIRouter()


@router.get(
    "",
    response_model=IdrDetectionRuleList,
    operation_id="list_detection_rules",
    summary="List InsightIDR detection rules",
    description=(
        "Returns detection rules configured in InsightIDR (from /idr/v1/rules). "
        "Each rule includes its name, description, MITRE tactics/techniques, "
        "priority level (HIGH/MEDIUM/LOW), state (ACTIVE/DISABLED), detection count, "
        "and last detected date. "
        "Use this to identify noisy rules generating false-positive investigations — "
        "for example, daily Sentinel correlation rules firing on expected international "
        "sign-ins. Filter by states=DISABLED to see suppressed rules. "
        "Pagination: pass the `cursor` from the previous response to get the next page."
    ),
)
async def list_detection_rules(
    states: str | None = Query(None, description="Filter by state: ACTIVE or DISABLED (comma-separated)"),
    rule_set: str | None = Query(None, description="Filter by rule set, e.g. DR"),
    size: int = Query(20, ge=1, le=100, description="Number of rules per page"),
    cursor: str | None = Query(None, description="Cursor from previous response `position` field for next page"),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrDetectionRuleList:
    params: dict = {"size": size}
    if states:
        params["states"] = states
    if rule_set:
        params["rule_set"] = rule_set
    if cursor:
        params["position"] = cursor
    data = await client.get("/idr/v1/rules", params=params)
    return IdrDetectionRuleList(**data)


@router.get(
    "/{rule_rrn}",
    response_model=IdrDetectionRule,
    operation_id="get_detection_rule",
    summary="Get a detection rule by RRN",
    description=(
        "Returns full detail for a single InsightIDR detection rule including its "
        "name, description, MITRE tactics and techniques, priority level, state, "
        "threats it belongs to, event types it covers, and detection/exception counts. "
        "Use list_detection_rules to find the rule RRN first. "
        "Use this when investigating a recurring false-positive alert pattern — "
        "the rule detail shows what conditions trigger it, which informs whether "
        "suppression or tuning is appropriate."
    ),
)
async def get_detection_rule(
    rule_rrn: str,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrDetectionRule:
    if not rule_rrn.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full rule RRN from list_detection_rules.",
        )
    data = await client.get(f"/idr/v1/rules/{rule_rrn}")
    return IdrDetectionRule(**data)
