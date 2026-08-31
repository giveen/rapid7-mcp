"""Shared test fixtures and configuration."""

import pytest
from fastapi.testclient import TestClient

from rapid7_mcp.client import (
    DemoInsightConnectClient,
    DemoInsightIDRClient,
    DemoInsightVMClient,
    DemoMetasploitClient,
    get_client,
    get_connect_client,
    get_idr_client,
    get_msp_client,
)
from rapid7_mcp.config import Settings, get_settings
from rapid7_mcp.main import app


def demo_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "insight_install": "local",
        "console_url": "https://test-console:3780",
        "username": "testuser",
        "password": "testpass",
        "verify_ssl": False,
        "demo_mode": True,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def client() -> TestClient:
    """TestClient with all dependencies overridden to demo mode (local install)."""
    settings = demo_settings()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_client] = lambda: DemoInsightVMClient(settings)
    app.dependency_overrides[get_connect_client] = lambda: DemoInsightConnectClient(settings)
    app.dependency_overrides[get_idr_client] = lambda: DemoInsightIDRClient(settings)
    app.dependency_overrides[get_msp_client] = lambda: DemoMetasploitClient(settings)

    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def cloud_client() -> TestClient:
    """TestClient wired to demo mode with insight_install=cloud."""
    settings = demo_settings(
        insight_install="cloud",
        vm_region="us",
        vm_api_key="test-key",
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_client] = lambda: DemoInsightVMClient(settings)
    app.dependency_overrides[get_connect_client] = lambda: DemoInsightConnectClient(settings)
    app.dependency_overrides[get_idr_client] = lambda: DemoInsightIDRClient(settings)
    app.dependency_overrides[get_msp_client] = lambda: DemoMetasploitClient(settings)

    yield TestClient(app)
    app.dependency_overrides.clear()
