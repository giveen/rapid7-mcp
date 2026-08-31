"""Tests for Automation (InsightConnect) routes."""

from fastapi.testclient import TestClient


def test_list_connect_jobs(client: TestClient) -> None:
    response = client.get("/connect/jobs")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "jobs" in data["data"]
    assert len(data["data"]["jobs"]) == 2
    assert data["data"]["jobs"][0]["status"] == "succeeded"


def test_get_connect_job(client: TestClient) -> None:
    response = client.get("/connect/jobs/job-001")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "job" in data["data"]
    assert data["data"]["job"]["id"] == "job-001"
    assert "outputs" in data["data"]["job"]


def test_list_connect_workflows(client: TestClient) -> None:
    response = client.get("/connect/workflows")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "workflows" in data["data"]
    assert len(data["data"]["workflows"]) == 2
    assert data["data"]["workflows"][0]["state"] == "active"


def test_get_connect_workflow(client: TestClient) -> None:
    response = client.get("/connect/workflows/wf-001")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["workflowId"] == "wf-001"
    assert data["data"]["publishedVersion"]["name"] == "Enrich Alert Data with Open Source Plugins"
