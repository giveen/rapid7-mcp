"""Tests for InsightVM client topology selection (local vs cloud)."""

import warnings

import pytest

from rapid7_mcp.client import InsightVMClient
from rapid7_mcp.config import Settings


@pytest.fixture(autouse=True)
def _reset_cloud_warning_flag() -> None:
    """Allow each test to observe the cloud-mode warning independently."""
    InsightVMClient._CLOUD_WARNING_EMITTED = False


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "console_url": "https://console.example:3780",
        "username": "u",
        "password": "p",
        "verify_ssl": False,
        "demo_mode": True,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_local_mode_uses_console_url_and_basic_auth() -> None:
    client = InsightVMClient(_settings(insight_install="local"))
    assert client.base_url == "https://console.example:3780/api/3"
    assert client._auth == ("u", "p")
    assert client._headers is None
    assert client._verify is False


def test_cloud_mode_uses_platform_url_and_api_key_header() -> None:
    client = InsightVMClient(
        _settings(
            insight_install="cloud",
            vm_region="eu",
            vm_api_key="test-key-xyz",
        )
    )
    assert client.base_url == "https://eu.api.insight.rapid7.com/vm/v1"
    assert client._auth is None
    assert client._headers is not None
    assert client._headers["X-Api-Key"] == "test-key-xyz"
    assert client._verify is True  # always verify for public-CA cloud TLS


def test_cloud_mode_emits_warning_once() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        InsightVMClient(_settings(insight_install="cloud", vm_api_key="k"))
        # Second construction with the flag still set should NOT re-warn
        InsightVMClient(_settings(insight_install="cloud", vm_api_key="k"))
    cloud_warnings = [w for w in caught if "/api/3" in str(w.message)]
    assert len(cloud_warnings) == 1


def test_local_mode_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        InsightVMClient(_settings(insight_install="local"))
    cloud_warnings = [w for w in caught if "/api/3" in str(w.message)]
    assert cloud_warnings == []


def test_request_kwargs_local() -> None:
    client = InsightVMClient(_settings(insight_install="local"))
    assert client._request_kwargs() == {"auth": ("u", "p")}


def test_request_kwargs_cloud() -> None:
    client = InsightVMClient(
        _settings(insight_install="cloud", vm_api_key="k")
    )
    kwargs = client._request_kwargs()
    assert "auth" not in kwargs
    assert kwargs["headers"]["X-Api-Key"] == "k"


def test_settings_default_install_is_local() -> None:
    s = Settings()
    assert s.insight_install == "local"
