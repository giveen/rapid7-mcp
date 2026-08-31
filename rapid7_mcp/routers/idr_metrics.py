"""InsightIDR SOC metrics router — pre-computed KPIs for a date range.

Paginates all investigations in the requested window and returns:
  - Counts by status, priority, source, responsibility
  - MTTR (mean/median time-to-resolve for closed investigations)
  - MTTA proxy (mean time from creation to last-access for assigned investigations)
  - Assigned vs unassigned breakdown

This avoids requiring the caller to page through raw investigation data themselves.
"""

import statistics
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.models import IdrMetrics

router = APIRouter()

_PAGE_SIZE = 100


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hours(delta_seconds: float) -> float:
    return round(delta_seconds / 3600, 2)


@router.get(
    "",
    response_model=IdrMetrics,
    operation_id="get_idr_metrics",
    summary="Get InsightIDR SOC metrics for a date range",
    description=(
        "Computes SOC KPIs across all InsightIDR investigations created in the given window. "
        "Returns total count, breakdowns by status/priority/source/responsibility, "
        "assigned vs unassigned counts, MTTR (mean and median hours for closed investigations), "
        "and a MTTA proxy (mean hours from creation to last-access for assigned investigations). "
        "Note: true MTTA requires acknowledgement timestamps not exposed in the investigation API; "
        "the proxy is a reasonable upper-bound approximation. "
        "Example: start_date=2026-07-01T00:00:00Z end_date=2026-07-31T23:59:59Z"
    ),
)
async def get_idr_metrics(
    start_date: str = Query(..., description="ISO-8601 window start, e.g. 2026-07-01T00:00:00Z"),
    end_date: str = Query(..., description="ISO-8601 window end, e.g. 2026-07-31T23:59:59Z"),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrMetrics:
    # --- Paginate all investigations in window ---
    all_investigations: list[dict] = []
    index = 0
    total_reported = None

    while True:
        payload = {
            "start_time": start_date,
            "end_time": end_date,
            "statuses": ["OPEN", "INVESTIGATING", "WAITING", "CLOSED"],
            "size": _PAGE_SIZE,
            "index": index,
        }
        data = await client.post("/idr/v2/investigations/_search", body=payload)
        page = data.get("data", [])
        all_investigations.extend(page)

        if total_reported is None:
            total_reported = data.get("metadata", {}).get("total_data", 0)

        if not page or len(all_investigations) >= (total_reported or 0):
            break
        index += _PAGE_SIZE

    total = len(all_investigations)

    # --- Breakdowns ---
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_responsibility: dict[str, int] = {}
    assigned_count = 0
    unassigned_count = 0

    mttr_seconds: list[float] = []
    mtta_seconds: list[float] = []

    for inv in all_investigations:
        status = inv.get("status", "UNKNOWN")
        priority = inv.get("priority", "UNKNOWN")
        source = inv.get("source", "UNKNOWN")
        responsibility = inv.get("responsibility", "UNKNOWN")
        assignee = inv.get("assignee")
        created = _parse_dt(inv.get("createdTime") or inv.get("created_time"))
        last_accessed = _parse_dt(inv.get("lastAccessed") or inv.get("last_accessed"))

        by_status[status] = by_status.get(status, 0) + 1
        by_priority[priority] = by_priority.get(priority, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_responsibility[responsibility] = by_responsibility.get(responsibility, 0) + 1

        if assignee:
            assigned_count += 1
        else:
            unassigned_count += 1

        if created and last_accessed and last_accessed > created:
            delta = (last_accessed - created).total_seconds()
            if status == "CLOSED":
                mttr_seconds.append(delta)
            if assignee:
                mtta_seconds.append(delta)

    # --- MTTR ---
    mttr_avg_hours = _hours(sum(mttr_seconds) / len(mttr_seconds)) if mttr_seconds else None
    mttr_median_hours = _hours(statistics.median(mttr_seconds)) if mttr_seconds else None

    # --- MTTA proxy ---
    mtta_avg_hours = _hours(sum(mtta_seconds) / len(mtta_seconds)) if mtta_seconds else None

    return IdrMetrics(
        period_start=start_date,
        period_end=end_date,
        total_investigations=total,
        by_status=by_status,
        by_priority=by_priority,
        by_source=by_source,
        by_responsibility=by_responsibility,
        assigned_count=assigned_count,
        unassigned_count=unassigned_count,
        closed_count=by_status.get("CLOSED", 0),
        mttr_avg_hours=mttr_avg_hours,
        mttr_median_hours=mttr_median_hours,
        mtta_avg_hours=mtta_avg_hours,
        mtta_note=(
            "MTTA is approximated as time from investigation creation to last-access for "
            "assigned investigations. True MTTA requires acknowledgement timestamps not "
            "exposed in the InsightIDR REST API; use the InsightIDR built-in dashboard "
            "for the authoritative value."
        ),
    )
