"""Cloud-mode tests for the InsightVM routers.

The fixtures in /tests/fixtures are shape-compatible with both v3 (local) and
v4 (cloud) response shapes since the cloud endpoints return raw dicts without
response_model validation.
"""

import pytest
from fastapi.testclient import TestClient

# --- sites router ---

def test_list_sites_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.get("/sites")
    assert r.status_code == 200
    body = r.json()
    assert "resources" in body or "data" in body  # either shape


def test_get_site_cloud_returns_501(cloud_client: TestClient) -> None:
    r = cloud_client.get("/sites/1")
    assert r.status_code == 501
    assert "cloud" in r.json()["detail"].lower()


# --- assets router ---

def test_get_asset_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.get("/assets/1")
    assert r.status_code == 200


def test_search_assets_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.post(
        "/assets/search",
        json={"filters": [{"field": "ip-address", "operator": "starts-with", "value": "10."}], "match": "all"},
    )
    assert r.status_code == 200


def test_get_asset_vulnerabilities_cloud_returns_501(cloud_client: TestClient) -> None:
    r = cloud_client.get("/assets/1/vulnerabilities")
    assert r.status_code == 501


def test_get_asset_tags_cloud_returns_501(cloud_client: TestClient) -> None:
    r = cloud_client.get("/assets/1/tags")
    assert r.status_code == 501


# --- vulnerabilities router ---

def test_list_vulnerabilities_cloud_returns_501(cloud_client: TestClient) -> None:
    r = cloud_client.get("/vulnerabilities")
    assert r.status_code == 501


def test_get_vulnerability_cloud_returns_501(cloud_client: TestClient) -> None:
    r = cloud_client.get("/vulnerabilities/CVE-2024-0001")
    assert r.status_code == 501


# --- scans router ---

def test_list_scans_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.get("/scans")
    assert r.status_code == 200


def test_get_scan_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.get("/scans/1")
    assert r.status_code == 200


# --- asset_groups / remediation / reports (all 501 in cloud) ---

@pytest.mark.parametrize("method,path", [
    ("get", "/asset_groups"),
    ("get", "/asset_groups/1"),
    ("get", "/remediation_projects"),
    ("get", "/remediation_projects/1"),
    ("get", "/reports"),
    ("get", "/reports/1"),
    ("post", "/reports/1/generate"),
])
def test_on_prem_only_routes_return_501_in_cloud(
    cloud_client: TestClient, method: str, path: str
) -> None:
    r = getattr(cloud_client, method)(path)
    assert r.status_code == 501
    assert "cloud" in r.json()["detail"].lower()


# --- vm_health (cloud only) ---

def test_get_vm_health_cloud(cloud_client: TestClient) -> None:
    r = cloud_client.get("/vm/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "UP"
    assert body["summary"]["up"] == 3
    assert body["summary"]["down"] == 0


def test_get_vm_health_local_returns_501(client: TestClient) -> None:
    r = client.get("/vm/health")
    assert r.status_code == 501
