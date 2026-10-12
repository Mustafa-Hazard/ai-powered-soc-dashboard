"""
test_api.py
Test suite for Phase 5 Web Dashboard API & Vercel serverless endpoints.
"""

import pytest
from starlette.testclient import TestClient
from web import app


@pytest.fixture
def client():
    return TestClient(app)

def test_serve_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "AI-POWERED SOC DASHBOARD" in response.text
    assert "SIEM DETECTION & GRC COMPLIANCE LAB" in response.text

def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["version"] == "2.0.0"
    assert "active_rules" in data

def test_get_alerts(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert data["total"] >= 1
    assert "overall_score" in data
    assert "overall_posture" in data

    # Test filtering
    filtered = client.get("/api/alerts?technique=T1110")
    assert filtered.status_code == 200
    filtered_data = filtered.json()
    for alert in filtered_data["alerts"]:
        assert alert["technique_id"] == "T1110"

def test_get_summary(client):
    response = client.get("/api/summary")
    assert response.status_code == 200
    data = response.json()
    assert "executive_summary" in data
    assert "attack_chain" in data
    assert "recommendations" in data
    assert len(data["attack_chain"]) >= 1

def test_get_matrix(client):
    response = client.get("/api/matrix")
    assert response.status_code == 200
    data = response.json()
    assert "matrix" in data
    technique_ids = {item["id"] for item in data["matrix"]}
    assert {"T1110", "T1078", "T1059"}.issubset(technique_ids)

def test_get_compliance(client):
    response = client.get("/api/compliance")
    assert response.status_code == 200
    data = response.json()
    assert "mappings" in data
    assert len(data["mappings"]) >= 3
    for m in data["mappings"]:
        assert "iso_control" in m
        assert "nist_control" in m

def test_run_triage(client):
    response = client.post("/api/triage/run", json={"use_dedup": False})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "alerts" in data

def test_simulation_scenarios(client):
    # Simulate T1110 brute force
    sim_t1110 = client.post("/api/simulate", json={"scenario": "t1110_brute_force", "attempts": 50})
    assert sim_t1110.status_code == 200
    data = sim_t1110.json()
    assert data["status"] == "success"

    # Simulate T1078 compromise
    sim_t1078 = client.post("/api/simulate", json={"scenario": "t1078_compromise", "prior_failed_attempts": 40})
    assert sim_t1078.status_code == 200

    # Simulate T1059 payload
    sim_t1059 = client.post("/api/simulate", json={"scenario": "t1059_payload", "command": "wget"})
    assert sim_t1059.status_code == 200

    # Simulate reset
    sim_reset = client.post("/api/simulate", json={"scenario": "reset"})
    assert sim_reset.status_code == 200

def test_alert_status_disposition(client):
    alerts_resp = client.get("/api/alerts")
    alerts = alerts_resp.json()["alerts"]
    assert len(alerts) > 0
    first_hash = alerts[0]["hash"]

    # Update disposition
    resp = client.post(f"/api/alerts/{first_hash}/status", json={"status": "Investigating"})
    assert resp.status_code == 200
    assert resp.json()["disposition"] == "Investigating"

    # Invalid status
    bad_resp = client.post(f"/api/alerts/{first_hash}/status", json={"status": "InvalidStatus"})
    assert bad_resp.status_code == 400

def test_ai_copilot_ask(client):
    resp = client.post("/api/ai/ask", json={"query": "Generate CISO incident brief"})
    assert resp.status_code == 200
    data = resp.json()
    assert "Executive Incident Brief" in data["response"]

    contain_resp = client.post("/api/ai/ask", json={"query": "How to contain attacker"})
    assert contain_resp.status_code == 200
    assert "iptables" in contain_resp.json()["response"]

def test_state_reset(client):
    resp = client.post("/api/state/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
