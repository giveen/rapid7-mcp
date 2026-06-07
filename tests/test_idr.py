"""Tests for the InsightIDR router."""

from fastapi.testclient import TestClient


def test_list_investigations(client: TestClient) -> None:
    response = client.get("/idr/investigations")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 2
    inv = data["data"][0]
    assert inv["status"] == "OPEN"
    assert inv["priority"] == "HIGH"
    assert "title" in inv


def test_list_investigations_filters(client: TestClient) -> None:
    response = client.get("/idr/investigations?status=INVESTIGATING&priority=CRITICAL")
    assert response.status_code == 200


def test_get_investigation(client: TestClient) -> None:
    response = client.get("/idr/investigations/INV-002")
    assert response.status_code == 200
    data = response.json()
    assert data["priority"] == "CRITICAL"
    assert data["status"] == "INVESTIGATING"
    assert data["assignee"] == "bob@example.com"


def test_query_logs(client: TestClient) -> None:
    payload = {
        "query": 'where(destination_ip = "185.220.101.1")',
        "from_time": 1705276800000,
        "to_time": 1705363200000,
        "logs": ["firewall-logs"],
    }
    response = client.post("/idr/logs", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert len(data["events"]) == 3


def test_list_indicators(client: TestClient) -> None:
    response = client.get("/idr/iocs")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 3
    ioc = data["data"][0]
    assert ioc["indicator_type"] == "IP_ADDRESS"
    assert ioc["active"] is True


def test_list_indicators_type_filter(client: TestClient) -> None:
    response = client.get("/idr/iocs?indicator_type=FILE_HASH")
    assert response.status_code == 200


def test_list_investigation_alerts(client: TestClient) -> None:
    response = client.get("/idr/investigations/INV-002/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 2
    alert = data["data"][0]
    assert alert["alertType"] == "Attacker Behavior Detected"
    assert alert["alertSource"] == "Endpoint Detection"
    assert alert["detectionRuleRrn"]["ruleName"] == "Suspicious PowerShell Activity"


def test_list_investigation_alerts_pagination(client: TestClient) -> None:
    response = client.get("/idr/investigations/INV-002/alerts?size=5&page_token=0")
    assert response.status_code == 200


def test_search_investigations(client: TestClient) -> None:
    payload = {
        "search": [
            {"field": "title", "operator": "CONTAINS", "value": "Brute Force"},
            {"field": "priority", "operator": "EQUALS", "value": "CRITICAL"},
        ],
        "sort": [{"field": "created_time", "order": "DESC"}],
        "start_time": "2024-01-01T00:00:00Z",
        "end_time": "2024-02-01T00:00:00Z",
    }
    response = client.post("/idr/investigations/_search", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 2


def test_search_investigations_empty(client: TestClient) -> None:
    response = client.post("/idr/investigations/_search", json={})
    assert response.status_code == 200


def test_list_logs(client: TestClient) -> None:
    response = client.get("/idr/logs")
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert len(data["logs"]) == 2
    log = data["logs"][0]
    assert log["name"] == "Firewall Logs"
    assert log["sourceType"] == "syslog"
    assert "id" in log


def test_get_health_metrics(client: TestClient) -> None:
    response = client.get("/idr/health_metrics")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 2
    assert "metadata" in data


def test_get_health_metrics_filters(client: TestClient) -> None:
    response = client.get(
        "/idr/health_metrics?resource_types=LogSearch&size=10&orgId=abc123"
    )
    assert response.status_code == 200
