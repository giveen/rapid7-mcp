"""Tests for the /assets/cloud/search endpoint (search_integration_assets)."""

from fastapi.testclient import TestClient


def test_cloud_search_defaults(cloud_client: TestClient) -> None:
    """Empty body should return fixture data with metadata."""
    response = cloud_client.post("/assets/cloud/search", json={})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "metadata" in data
    assert isinstance(data["data"], list)
    assert len(data["data"]) == 2  # fixture has 2 assets
    assert data["metadata"]["totalResources"] == 12697


def test_cloud_search_with_leql_filter(cloud_client: TestClient) -> None:
    """LEQL filter in body is accepted and fixture still returned in demo mode."""
    response = cloud_client.post(
        "/assets/cloud/search",
        json={"asset": "asset.os_family = 'Windows'", "size": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["data"][0]["os_family"] == "Windows"
    assert data["data"][0]["host_name"] == "prod-sql1.example.com"


def test_cloud_search_asset_fields(cloud_client: TestClient) -> None:
    """Verify full asset schema fields are present."""
    response = cloud_client.post("/assets/cloud/search", json={})
    asset = response.json()["data"][0]
    assert asset["critical_vulnerabilities"] == 214
    assert asset["total_vulnerabilities"] == 399
    assert asset["os_family"] == "Windows"
    assert isinstance(asset["tags"], list)
    assert asset["tags"][0]["name"] == "Production"
    assert isinstance(asset["unique_identifiers"], list)
    assert asset["unique_identifiers"][0]["source"] == "R7 Agent"
    assert isinstance(asset["credential_assessments"], list)


def test_cloud_search_with_sort(cloud_client: TestClient) -> None:
    """Sort parameter is accepted."""
    response = cloud_client.post(
        "/assets/cloud/search",
        json={"sort": [{"field": "risk-score", "order": "DESC"}]},
    )
    assert response.status_code == 200


def test_cloud_search_with_cursor(cloud_client: TestClient) -> None:
    """Cursor pagination parameter is accepted."""
    response = cloud_client.post(
        "/assets/cloud/search",
        json={"cursor": "demo-cursor-page2"},
    )
    assert response.status_code == 200
    assert "data" in response.json()


def test_cloud_search_metadata_shape(cloud_client: TestClient) -> None:
    """Metadata contains expected pagination fields."""
    response = cloud_client.post("/assets/cloud/search", json={})
    meta = response.json()["metadata"]
    assert "totalResources" in meta
    assert "cursor" in meta


def test_cloud_search_requires_cloud_mode(client: TestClient) -> None:
    """Endpoint should return 501 when insight_install != cloud."""
    response = client.post("/assets/cloud/search", json={})
    assert response.status_code == 501
