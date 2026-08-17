from pydantic import BaseModel, Field

from rapid7_mcp.models.shared import Link, SearchCriterion


class Assignee(BaseModel):
    name: str | None = None
    email: str | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class Investigation(BaseModel):
    rrn: str
    organization_id: str = Field(alias="organizationId")
    title: str
    source: str
    status: str
    priority: str
    last_accessed: str = Field(alias="lastAccessed")
    created_time: str = Field(alias="createdTime")
    disposition: str
    assignee: str | Assignee | None = None
    first_alert_time: str | None = Field(None, alias="firstAlertTime")
    latest_alert_time: str | None = Field(None, alias="latestAlertTime")
    tags: list[str] = []
    responsibility: str | None = None

    model_config = {"populate_by_name": True}


class InvestigationList(BaseModel):
    data: list[Investigation] = []
    metadata: dict = {}


class DetectionRule(BaseModel):
    rule_name: str = Field(alias="ruleName")
    rule_rrn: str = Field(alias="ruleRrn")

    model_config = {"populate_by_name": True}


class InvestigationAlert(BaseModel):
    id: str
    title: str
    alert_type: str = Field(alias="alertType")
    alert_type_description: str = Field(alias="alertTypeDescription")
    created_time: str = Field(alias="createdTime")
    first_event_time: str | None = Field(None, alias="firstEventTime")
    latest_event_time: str | None = Field(None, alias="latestEventTime")
    alert_source: str = Field(alias="alertSource")
    detection_rule_rrn: DetectionRule | None = Field(None, alias="detectionRuleRrn")

    model_config = {"populate_by_name": True}


class InvestigationAlertList(BaseModel):
    data: list[InvestigationAlert] = []
    metadata: dict = {}


class InvestigationSort(BaseModel):
    field: str
    order: str


class InvestigationSearchRequest(BaseModel):
    search: list[SearchCriterion] = []
    sort: list[InvestigationSort] = []
    start_time: str | None = None
    end_time: str | None = None


class HealthMetric(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}


class HealthMetricList(BaseModel):
    data: list[HealthMetric] = []
    metadata: dict = {}


class LogSearchRequest(BaseModel):
    query: str
    from_time: int | None = None
    to_time: int | None = None
    time_range: str | None = None
    logs: list[str] = []


class LogEntry(BaseModel):
    message: str
    timestamp: int
    log_id: str = Field(alias="logId")
    sequence_number: int = Field(alias="sequenceNumber")
    sequence_number_str: str = Field(alias="sequenceNumberStr")
    labels: list[dict] | None = None
    links: list[Link] = []
    kvp_info: dict | None = Field(None, alias="kvpInfo")

    model_config = {"populate_by_name": True}


class LogSearchResults(BaseModel):
    logs: list[str] = []
    leql: dict = {}
    events: list[LogEntry] = []
    id: str | None = None
    progress: int | None = None
    links: list[Link] = []


class LogInfo(BaseModel):
    id: str
    name: str
    rrn: str | None = None
    source_type: str | None = Field(None, alias="sourceType")
    retention_period: str | None = Field(None, alias="retentionPeriod")
    tokens: list[str] = []
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class LogInfoList(BaseModel):
    logs: list[LogInfo] = []


class Indicator(BaseModel):
    id: str | None = None
    indicator_value: str
    indicator_type: str
    source: str | None = None
    threat: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    active: bool = True

    model_config = {"populate_by_name": True}


class IndicatorList(BaseModel):
    data: list[Indicator] = []
    metadata: dict = {}


# ---------------------------------------------------------------------------
# Investigation triage write models
# ---------------------------------------------------------------------------


class AssignInvestigationRequest(BaseModel):
    email: str = Field(..., description="Email address of the analyst to assign")


class BulkCloseRequest(BaseModel):
    """Criteria for bulk-closing investigations (POST /idr/v2/investigations/bulk_close).

    When source is ALERT (the most common case), either alert_type or
    detection_rule_rrn is required by the Rapid7 API.
    """

    alert_type: str | None = Field(None, description="Close only investigations of this alert type (required when source=ALERT)")
    detection_rule_rrn: str | None = Field(None, description="Close only investigations from this detection rule RRN (alternative to alert_type)")
    source: str | None = Field(None, description="Source filter: ALERT, MANUAL, HUNT")
    disposition: str | None = Field(None, description="Set this disposition when closing: BENIGN, MALICIOUS, NOT_APPLICABLE, UNDECIDED")
    from_time: str | None = Field(None, alias="from", description="ISO-8601 start of time window")
    to_time: str | None = Field(None, alias="to", description="ISO-8601 end of time window")
    max_investigations_to_close: int | None = Field(None, ge=1, le=10000, description="Cap on how many to close (max 10 000)")

    model_config = {"populate_by_name": True}


class BulkCloseResponse(BaseModel):
    num_closed: int = Field(0, alias="numClosed")
    model_config = {"populate_by_name": True, "extra": "allow"}


class AddCommentRequest(BaseModel):
    body: str = Field(..., description="Markdown comment body")
    target: str = Field(..., description="Investigation RRN to attach the comment to")
    visibility: str = Field("public", description="Comment visibility: public or private")


class IdrComment(BaseModel):
    rrn: str | None = None
    body: str | None = None
    target: str | None = None
    visibility: str | None = None
    created_time: str | None = Field(None, alias="createdTime")
    author: dict | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrCommentList(BaseModel):
    data: list[IdrComment] = []
    metadata: dict = {}


# ---------------------------------------------------------------------------
# IDR entity context models (accounts / users)
# ---------------------------------------------------------------------------


class IdrEntitySearchRequest(BaseModel):
    search: list[SearchCriterion] = []
    sort: list[dict] = []
    size: int | None = Field(None, ge=1, le=500, description="Number of results per page")


class IdrAccount(BaseModel):
    rrn: str | None = None
    name: str | None = None
    domain: str | None = None
    account_type: str | None = Field(None, alias="accountType")
    privileged: bool | None = None
    locked: bool | None = None
    disabled: bool | None = None
    last_authentication_time: str | None = Field(None, alias="lastAuthenticationTime")

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrAccountList(BaseModel):
    data: list[IdrAccount] = []
    metadata: dict = {}


class IdrUser(BaseModel):
    """InsightIDR UBA user — returned by /idr/v1/users/_search."""

    rrn: str | None = None
    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrUserList(BaseModel):
    data: list[IdrUser] = []
    metadata: dict = {}


# ---------------------------------------------------------------------------
# IDR asset models
# ---------------------------------------------------------------------------


class IdrAsset(BaseModel):
    """InsightIDR UBA asset — returned by /idr/v1/assets/_search."""

    rrn: str | None = None
    name: str | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrAssetList(BaseModel):
    data: list[IdrAsset] = []
    metadata: dict = {}


# ---------------------------------------------------------------------------
# Detection Rules models  (/idr/v1/rules — real path, not /idr/v1/detection-rules)
# ---------------------------------------------------------------------------


class IdrDetectionRuleState(BaseModel):
    value: str | None = None  # ACTIVE | DISABLED
    reason: str | None = None


class IdrDetectionRuleThreat(BaseModel):
    rrn: str | None = None
    name: str | None = None
    description: str | None = None
    detection_rule_count: int | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrDetectionRuleDetail(BaseModel):
    """The nested `rule` object inside a detection rule."""

    name: str | None = None
    description: str | None = None
    recommendation: str | None = None
    rule_action: str | None = None
    priority_level: str | None = None
    tactics: list[str] = []
    techniques: list[str] = []

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrDetectionRule(BaseModel):
    """A single InsightIDR detection rule from /idr/v1/rules."""

    rrn: str | None = None
    rule_set: str | None = None
    state: IdrDetectionRuleState | None = None
    rule: IdrDetectionRuleDetail | None = None
    threats: list[IdrDetectionRuleThreat] = []
    event_types: list[str] = []
    detection_count: int | None = None
    create_date: str | None = None
    last_modified_date: str | None = None
    last_detected_date: str | None = None
    responsibility: str | None = None
    exception_count: int | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class IdrDetectionRuleList(BaseModel):
    data: list[IdrDetectionRule] = []
    metadata: dict = {}
    position: str | None = None  # cursor for next page
