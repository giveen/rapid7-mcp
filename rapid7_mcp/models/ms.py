from pydantic import BaseModel


class Workspace(BaseModel):
    id: int
    name: str
    description: str | None = None
    boundary: str | None = None
    limit_to_network: bool = False
    hosts_count: int = 0
    credentials_count: int = 0
    sessions_count: int = 0

    model_config = {"populate_by_name": True}


class WorkspaceList(BaseModel):
    data: list[Workspace] = []


class Session(BaseModel):
    id: int
    session_type: str | None = None
    tunnel_local: str | None = None
    tunnel_peer: str | None = None
    via_exploit: str | None = None
    via_payload: str | None = None
    desc: str | None = None
    info: str | None = None
    workspace: str | None = None
    target_host: str | None = None
    target_port: int | None = None
    username: str | None = None
    uuid: str | None = None
    opened_at: str | None = None
    last_checkin: str | None = None
    platform: str | None = None
    arch: str | None = None
    os_name: str | None = None

    model_config = {"populate_by_name": True}


class SessionList(BaseModel):
    data: list[Session] = []


class LootEntry(BaseModel):
    id: int
    host: str | None = None
    port: int | None = None
    service_name: str | None = None
    loot_type: str | None = None
    data: str | None = None
    content_type: str | None = None
    name: str | None = None
    info: str | None = None
    workspace: str | None = None
    created_at: str | None = None

    model_config = {"populate_by_name": True}


class LootList(BaseModel):
    data: list[LootEntry] = []


class MspTask(BaseModel):
    id: int
    status: str | None = None
    task_type: str | None = None
    description: str | None = None
    progress: int = 0
    workspace: str | None = None
    created_at: str | None = None
    completed_at: str | None = None
    error: str | None = None

    model_config = {"populate_by_name": True}


class MspTaskList(BaseModel):
    data: list[MspTask] = []
