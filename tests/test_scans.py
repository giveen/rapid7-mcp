"""Tests for the scans router using demo mode fixtures."""

from fastapi.testclient import TestClient


def test_list_scans(client: TestClient) -> None:
    response = client.get("/scans")
    assert response.status_code == 200
    data = response.json()
    assert "resources" in data
    assert len(data["resources"]) == 2
    scan = data["resources"][0]
    assert scan["siteName"] == "Production Network"
    assert scan["status"] == "finished"


def test_list_scans_active_filter(client: TestClient) -> None:
    response = client.get("/scans?active=true")
    assert response.status_code == 200
    data = response.json()
    assert "resources" in data


def test_get_scan(client: TestClient) -> None:
    response = client.get("/scans/101")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_cloud_only_scan_engine_routes_return_501_in_local_mode(client: TestClient) -> None:
    response = client.get("/scans/engine")
    assert response.status_code == 501


def test_cloud_only_scan_start_stop_routes_return_501_in_local_mode(client: TestClient) -> None:
    start = client.post("/scans", json={"name": "test-scan"})
    assert start.status_code == 501
    stop = client.post("/scans/scan-123/stop")
    assert stop.status_code == 501
