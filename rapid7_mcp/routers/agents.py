"""InsightVM Insight Agent roster router.

Returns the count of assets that have the Rapid7 Insight Agent installed,
as reported by the InsightVM cloud integration API.

The cloud integration API (/vm/v4/integration/assets) surfaces only assets
that have been assessed via the Insight Platform — which in practice means
assets with at least one Insight Agent identifier.  The totalResources from
that endpoint therefore reflects the Rapid7 agent count for the tenant.

Non-agent assets (scanned exclusively via scan-engine credential sweeps)
are tracked in the on-prem InsightVM console and are not exposed through
the cloud integration API; their count must be read from the console directly.
"""

from fastapi import APIRouter, Depends

from rapid7_mcp.client import InsightVMClient, get_client
from rapid7_mcp.models import AgentSummary

router = APIRouter()


@router.get(
    "",
    response_model=AgentSummary,
    operation_id="get_agent_summary",
    summary="Get Rapid7 Insight Agent count from InsightVM",
    description=(
        "Returns the total number of assets with a Rapid7 Insight Agent installed, "
        "as reported by the InsightVM cloud integration API. "
        "The cloud API surfaces only agent-assessed assets, so totalResources equals "
        "the agent count for the tenant. "
        "Non-agent assets scanned exclusively via scan-engine credential sweeps are "
        "not accessible through the cloud API; their count must be read from the "
        "on-prem InsightVM console (Assets → filter by site 'Intrastructure - Non Agents'). "
        "Use this to answer: 'How many Rapid7 agents do we have deployed?' or "
        "'What is our total agent-covered asset count?'"
    ),
)
async def get_agent_summary(
    client: InsightVMClient = Depends(get_client),
) -> AgentSummary:
    # POST with empty body returns first page; totalResources is the agent count
    data = await client.post("/v4/integration/assets", body={})
    metadata = data.get("metadata", {})
    total_agents = metadata.get("totalResources", 0)

    return AgentSummary(
        total_agents=total_agents,
        source="InsightVM cloud integration API — agent-assessed assets only",
        note=(
            "Non-agent assets (scan-engine only) are not returned by this API. "
            "Check the InsightVM console for non-agent scanned asset counts."
        ),
    )
