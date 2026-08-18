from typing import Any

from pydantic import BaseModel, Field

from rapid7_mcp.models.shared import Link, PageInfo, SearchCriterion

# ---------------------------------------------------------------------------
# InsightVM v4 Cloud Integration API — Asset models
# These match the /vm/v4/integration/assets response shape exactly.
# ---------------------------------------------------------------------------


class CloudAssetTag(BaseModel):
    name: str | None = None
    type: str | None = None  # OWNER | SITE | CUSTOM | ...

    model_config = {"extra": "allow"}


class CloudAssetUniqueIdentifier(BaseModel):
    id: str | None = None
    source: str | None = None  # R7 Agent | Endpoint Agent | active-directory | CSPRODUCT | ...

    model_config = {"extra": "allow"}


class CloudAssetCredentialAssessment(BaseModel):
    port: int | None = None
    protocol: str | None = None
    status: str | None = None  # SUPPLIED_FAILED | NO_CREDS_SUPPLIED | SUCCESS | ...

    model_config = {"extra": "allow"}


class CloudAssetSort(BaseModel):
    field: str = Field(..., description="Sort field, e.g. 'risk-score'")
    order: str = Field("DESC", description="Sort direction: ASC or DESC")


class CloudAsset(BaseModel):
    """A single asset from the InsightVM v4 Cloud Integration API."""

    id: str | None = None
    host_name: str | None = None
    ip: str | None = None
    mac: str | None = None
    os_family: str | None = None
    os_name: str | None = None
    os_description: str | None = None
    os_vendor: str | None = None
    os_version: str | None = None
    os_architecture: str | None = None
    os_system_name: str | None = None
    os_type: str | None = None
    risk_score: float | None = None
    critical_vulnerabilities: int | None = None
    severe_vulnerabilities: int | None = None
    moderate_vulnerabilities: int | None = None
    total_vulnerabilities: int | None = None
    exploits: int | None = None
    malware_kits: int | None = None
    assessed_for_vulnerabilities: bool | None = None
    assessed_for_policies: bool | None = None
    last_assessed_for_vulnerabilities: str | None = None
    last_scan_start: str | None = None
    last_scan_end: str | None = None
    type: str | None = None  # guest | host
    tags: list[CloudAssetTag] = []
    unique_identifiers: list[CloudAssetUniqueIdentifier] = []
    credential_assessments: list[CloudAssetCredentialAssessment] = []

    model_config = {"populate_by_name": True, "extra": "allow"}


class CloudAssetMetadata(BaseModel):
    number: int | None = None
    size: int | None = None
    total_resources: int | None = Field(None, alias="totalResources")
    total_pages: int | None = Field(None, alias="totalPages")
    cursor: str | None = None
    effective_time: str | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class CloudAssetList(BaseModel):
    """Paginated asset list from the InsightVM v4 Cloud Integration API."""

    data: list[CloudAsset] = []
    metadata: CloudAssetMetadata = Field(default_factory=lambda: CloudAssetMetadata.model_construct())
    links: list[Link] = []


class CloudAssetSearchRequest(BaseModel):
    """Request body for POST /vm/v4/integration/assets (searchIntegrationAssets).

    The ``asset`` field accepts a LEQL expression to filter results.
    Leave empty to return all assets (paginated).

    LEQL filter examples:
      - ``asset.os_family = 'Windows'``
      - ``asset.os_family = 'Linux'``
      - ``asset.host_name contains 'web'``
      - ``asset.risk_score > 50000``
      - ``asset.os_family = 'Windows' && asset.risk_score > 10000``
    """

    asset: str | None = Field(
        None,
        description=(
            "LEQL filter expression. Examples: "
            "\"asset.os_family = 'Windows'\", "
            "\"asset.host_name contains 'prod'\", "
            "\"asset.risk_score > 50000\""
        ),
    )
    sort: list[CloudAssetSort] = Field(
        default_factory=list,
        description="Sort order, e.g. [{\"field\": \"risk-score\", \"order\": \"DESC\"}]",
    )
    size: int = Field(
        10,
        ge=1,
        le=100,
        description="Page size (1–100, default 10)",
    )


class Site(BaseModel):
    id: int
    name: str
    description: str | None = None
    assets: int = 0
    last_scan_time: str | None = Field(None, alias="lastScanTime")
    risk_score: float = Field(0.0, alias="riskScore")
    scan_template: str | None = Field(None, alias="scanTemplate")
    type: str | None = None
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class SiteList(BaseModel):
    page: PageInfo
    resources: list[Site]
    links: list[Link] = []


class OperatingSystem(BaseModel):
    description: str | None = None
    family: str | None = None
    name: str | None = None
    vendor: str | None = None
    version: str | None = None


class VulnerabilityCounts(BaseModel):
    critical: int = 0
    exploits: int = 0
    high: int = 0
    info: int = 0
    low: int = 0
    malware_kits: int = Field(0, alias="malwareKits")
    medium: int = 0
    severe: int = 0
    total: int = 0

    model_config = {"populate_by_name": True}


class Asset(BaseModel):
    id: int
    ip: str | None = None
    host_name: str | None = Field(None, alias="hostName")
    os: OperatingSystem | None = None
    vulnerabilities: VulnerabilityCounts | None = None
    risk_score: float = Field(0.0, alias="riskScore")
    last_scan_time: str | None = Field(None, alias="lastScanTime")
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class AssetList(BaseModel):
    page: PageInfo
    resources: list[Asset]
    links: list[Link] = []


class AssetSearchRequest(BaseModel):
    filters: list[SearchCriterion] = []
    match: str = "all"
    cloud_query: str | None = None


class CvssScore(BaseModel):
    access_complexity: str | None = Field(None, alias="accessComplexity")
    access_vector: str | None = Field(None, alias="accessVector")
    authentication: str | None = None
    availability_impact: str | None = Field(None, alias="availabilityImpact")
    confidentiality_impact: str | None = Field(None, alias="confidentialityImpact")
    exploit_score: float | None = Field(None, alias="exploitScore")
    impact_score: float | None = Field(None, alias="impactScore")
    integrity_impact: str | None = Field(None, alias="integrityImpact")
    score: float | None = None
    vector: str | None = None

    model_config = {"populate_by_name": True}


class Cvss(BaseModel):
    v2: CvssScore | None = None
    v3: CvssScore | None = None


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str | None = None
    severity: str | None = None
    severity_score: float | None = Field(None, alias="severityScore")
    risk_score: float | None = Field(None, alias="riskScore")
    cvss: Cvss | None = None
    cvss_v2: float | None = Field(None, alias="cvssV2Score")
    cvss_v3: float | None = Field(None, alias="cvssV3Score")
    exploits: int = 0
    malware_kits: int = Field(0, alias="malwareKits")
    published: str | None = None
    added: str | None = None
    modified: str | None = None
    categories: list[str] = []
    cves: list[str] = []
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class VulnerabilityList(BaseModel):
    page: PageInfo
    resources: list[Vulnerability]
    links: list[Link] = []


class AssetVulnerability(BaseModel):
    id: str
    instances: int = 0
    results: list[Any] = []
    since: str | None = None
    status: str | None = None
    links: list[Link] = []


class AssetVulnerabilityList(BaseModel):
    page: PageInfo
    resources: list[AssetVulnerability]
    links: list[Link] = []


class Scan(BaseModel):
    id: int
    site_id: int = Field(0, alias="siteId")
    site_name: str | None = Field(None, alias="siteName")
    scan_name: str | None = Field(None, alias="scanName")
    status: str | None = None
    start_time: str | None = Field(None, alias="startTime")
    end_time: str | None = Field(None, alias="endTime")
    duration: str | None = None
    assets_scanned: int = Field(0, alias="assets")
    vulnerabilities: VulnerabilityCounts | None = None
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class ScanList(BaseModel):
    page: PageInfo
    resources: list[Scan]
    links: list[Link] = []


class ScanStartRequest(BaseModel):
    asset_ids: list[str] | None = None
    credential_sources: list[str] | None = None
    engine_ids: list[str] | None = None
    exclusions: list[str] | None = None
    name: str | None = None
    result_consumer: str | None = None
    solution_ids: list[str] | None = None
    start_time: str | None = None
    vulnerability_ids: list[str] | None = None


class ScanEngineConfigurationUpdateRequest(BaseModel):
    properties: list[str]


class ScanEngineConfigurationRemoveRequest(BaseModel):
    properties: list[str]


class AssetGroup(BaseModel):
    id: int
    name: str
    description: str | None = None
    type: str | None = None
    assets: int = 0
    risk_score: float = Field(0.0, alias="riskScore")
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class AssetGroupList(BaseModel):
    page: PageInfo
    resources: list[AssetGroup]
    links: list[Link] = []


class AssetTag(BaseModel):
    id: int
    name: str
    color: str | None = None
    tag_type: str | None = Field(None, alias="type")
    created_by: str | None = Field(None, alias="createdBy")
    risk_modifier: str | None = Field(None, alias="riskModifier")
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class AssetTagList(BaseModel):
    page: PageInfo
    resources: list[AssetTag]
    links: list[Link] = []


class RemediationProject(BaseModel):
    id: int
    name: str
    description: str | None = None
    status: str | None = None
    owner: str | None = None
    due_date: str | None = Field(None, alias="dueDate")
    completed: bool = False
    asset_count: int = Field(0, alias="assets")
    vulnerability_count: int = Field(0, alias="vulnerabilities")
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class RemediationProjectList(BaseModel):
    page: PageInfo
    resources: list[RemediationProject]
    links: list[Link] = []


class Report(BaseModel):
    id: int
    name: str
    format: str | None = None
    status: str | None = None
    scope: dict | None = None
    template: str | None = None
    uri: str | None = None
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class ReportList(BaseModel):
    page: PageInfo
    resources: list[Report]
    links: list[Link] = []


class ReportGenerateResponse(BaseModel):
    id: int
    status: str
    uri: str | None = None
    links: list[Link] = []

    model_config = {"populate_by_name": True}


class VmHealthSummary(BaseModel):
    up: int | None = None
    down: int | None = None
    out_of_service: int | None = Field(None, alias="outOfService")
    unknown: int | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class VmHealth(BaseModel):
    status: str
    duration: float | None = None
    components: dict[str, Any] | None = None
    summary: VmHealthSummary | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class AgentSummary(BaseModel):
    """Rapid7 Insight Agent deployment summary from the InsightVM cloud API."""

    total_agents: int = 0
    source: str = ""
    note: str = ""
