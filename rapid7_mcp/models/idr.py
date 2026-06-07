from pydantic import BaseModel, Field

from rapid7_mcp.models.shared import Link, SearchCriterion


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
    assignee: str | None = None
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
