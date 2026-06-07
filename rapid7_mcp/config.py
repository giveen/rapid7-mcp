from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="R7_",
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
    )

    # InsightVM deployment topology
    # 'local'  -> on-prem console, Basic Auth, /api/3/* paths
    # 'cloud'  -> Insight Platform (managed), X-Api-Key, /vm/v1/* paths
    #            (routers not yet rewired — see warning in InsightVMClient)
    insight_install: Literal["local", "cloud"] = Field(
        default="local", validation_alias="R7_INSIGHT_INSTALL"
    )

    # InsightVM (on-prem console, Basic Auth) — used when insight_install=local
    console_url: str = "https://localhost:3780"
    username: str = "admin"
    password: str = "password"
    verify_ssl: bool = False

    # InsightVM (Insight Platform cloud, X-Api-Key) — used when insight_install=cloud
    vm_region: str = Field(default="us", validation_alias="R7_VM_REGION")
    vm_api_key: str = Field(default="", validation_alias="R7_VM_API_KEY")

    # InsightIDR (Insight Platform cloud API, X-Api-Key)
    idr_region: str = Field(default="us", validation_alias="IDR_REGION")
    idr_api_key: str = Field(default="", validation_alias="IDR_API_KEY")

    # Metasploit Pro (local/remote MSP console, token auth, read-only)
    msp_url: str = Field(default="https://localhost:3790", validation_alias="MSP_URL")
    msp_token: str = Field(default="", validation_alias="MSP_TOKEN")
    msp_verify_ssl: bool = Field(default=False, validation_alias="MSP_VERIFY_SSL")

    # Demo mode — return fixture data, skip all live connectivity
    demo_mode: bool = Field(default=False, validation_alias="DEMO_MODE")


@lru_cache
def get_settings() -> Settings:
    return Settings()
