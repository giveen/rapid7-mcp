"""Automation (InsightConnect) API models."""

from pydantic import BaseModel, Field


class ConnectMeta(BaseModel):
    limit: int = 0
    offset: int = 0
    total: int = 0

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectJob(BaseModel):
    id: str
    status: str | None = None
    user_assigned_status: str | None = Field(None, alias="userAssignedStatus")
    name: str | None = None
    workflow_version_id: str | None = Field(None, alias="workflowVersionId")
    started_at: str | None = Field(None, alias="startedAt")
    updated_at: str | None = Field(None, alias="updatedAt")
    ended_at: str | None = Field(None, alias="endedAt")
    owned_by_id: str | None = Field(None, alias="ownedById")
    image_data: str | None = Field(None, alias="imageData")
    owner: str | None = None
    step_error_count: int | None = Field(None, alias="stepErrorCount")
    duration: int | None = None
    tags: list[str] = []
    inputs: dict | None = None
    outputs: dict | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectJobListData(BaseModel):
    jobs: list[ConnectJob] = []
    meta: ConnectMeta = ConnectMeta()

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectJobList(BaseModel):
    data: ConnectJobListData = ConnectJobListData()

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectJobDetailData(BaseModel):
    job: ConnectJob

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectJobDetail(BaseModel):
    data: ConnectJobDetailData

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectWorkflowVersion(BaseModel):
    name: str | None = None
    summary: str | None = None
    tags: list[str] = []
    created_at: str | None = Field(None, alias="createdAt")
    created_by_name: str | None = Field(None, alias="createdByName")
    created_by_id: str | None = Field(None, alias="createdById")
    updated_at: str | None = Field(None, alias="updatedAt")
    updated_by_name: str | None = Field(None, alias="updatedByName")
    updated_by_id: str | None = Field(None, alias="updatedById")
    activated_at: str | None = Field(None, alias="activatedAt")
    activated_by_name: str | None = Field(None, alias="activatedByName")
    activated_by_id: str | None = Field(None, alias="activatedById")

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectWorkflow(BaseModel):
    workflow_id: str = Field(alias="workflowId")
    state: str | None = None
    published_version: ConnectWorkflowVersion | None = Field(None, alias="publishedVersion")
    unpublished_version: ConnectWorkflowVersion | None = Field(
        None, alias="unpublishedVersion"
    )
    rrn: str | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectWorkflowListData(BaseModel):
    workflows: list[ConnectWorkflow] = []
    meta: ConnectMeta = ConnectMeta()

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectWorkflowList(BaseModel):
    data: ConnectWorkflowListData = ConnectWorkflowListData()

    model_config = {"populate_by_name": True, "extra": "allow"}


class ConnectWorkflowDetail(BaseModel):
    data: ConnectWorkflow

    model_config = {"populate_by_name": True, "extra": "allow"}
