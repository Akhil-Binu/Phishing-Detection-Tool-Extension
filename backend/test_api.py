import sys
import os
from fastapi.testclient import TestClient

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import app

# Create a TestClient
client = TestClient(app)

def run_tests():
    print("=== Phishing Detection Tool - Running API Tests ===")
    
    # 1. Test Health Endpoint
    print("\n[1/4] Testing GET /api/health...")
    res = client.get("/api/health")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print("Health response:", data)
    assert data["status"] == "healthy"
    assert data["models_loaded"] is True
    print("[OK] Health check test passed.")

    # 2. Test URL Scanning Endpoint
    print("\n[2/4] Testing POST /api/scan/url...")
    
    # Case A: Safe URL
    safe_url = "https://google.com/search?q=cybersecurity"
    res = client.post("/api/scan/url", json={"url": safe_url})
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"Safe URL scan result for '{safe_url}':")
    print(f"  Threat score: {data['threat_score']}")
    print(f"  Risk level: {data['risk_level']}")
    print(f"  Triggers: {data['all_triggers']}")
    assert data["risk_level"] == "safe", f"Expected 'safe', got '{data['risk_level']}'"
    assert data["is_phishing"] is False
    print("[OK] Safe URL scan test passed.")
    
    # Case B: Typosquatted Domain (Heuristic Flagged)
    typo_url = "http://paypa1-security-login.com/signin"
    res = client.post("/api/scan/url", json={"url": typo_url})
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"Typosquatted URL scan result for '{typo_url}':")
    print(f"  Threat score: {data['threat_score']}")
    print(f"  Risk level: {data['risk_level']}")
    print(f"  Triggers: {data['all_triggers']}")
    assert data["risk_level"] == "danger", f"Expected 'danger', got '{data['risk_level']}'"
    assert data["is_phishing"] is True
    assert any("Typosquatting" in t for t in data["all_triggers"])
    print("[OK] Typosquatted URL scan test passed.")

    # 3. Test Email Scanning Endpoint
    print("\n[3/4] Testing POST /api/scan/email...")
    
    # Case A: Safe Workspace Email
    safe_email = "Hi Akhil, here is the weekly project status report. Let's discuss it in our sync tomorrow. Best, John."
    res = client.post("/api/scan/email", json={"text": safe_email})
    assert res.status_code == 200
    data = res.json()
    print(f"Safe Email analysis results:")
    print(f"  Threat score: {data['threat_score']}")
    print(f"  Risk level: {data['risk_level']}")
    assert data["risk_level"] == "safe"
    assert data["is_phishing"] is False
    print("[OK] Safe email analysis test passed.")
    
    # Case B: Phishing Urgent Request
    phish_email = "URGENT NOTICE: Your account billing details have expired! Verify your credentials immediately at http://verify-bank.com to avoid suspension."
    res = client.post("/api/scan/email", json={"text": phish_email})
    assert res.status_code == 200
    data = res.json()
    print(f"Phishing Email analysis results:")
    print(f"  Threat score: {data['threat_score']}")
    print(f"  Risk level: {data['risk_level']}")
    print(f"  Triggers: {data['triggers']}")
    assert data["risk_level"] == "danger"
    assert data["is_phishing"] is True
    print("[OK] Phishing email analysis test passed.")

    # 4. Test Domain Reputation Endpoint
    print("\n[4/4] Testing GET /api/scan/domain/{domain}...")
    
    # Test safe domain
    res = client.get("/api/scan/domain/wikipedia.org")
    assert res.status_code == 200
    data = res.json()
    print(f"Safe domain details for wikipedia.org:")
    print(f"  Reputation score: {data['reputation_score']}")
    print(f"  Status: {data['status']}")
    assert data["status"] == "safe"
    
    # Test typosquatted/suspicious domain
    res = client.get("/api/scan/domain/go0gle.xyz")
    assert res.status_code == 200
    data = res.json()
    print(f"Suspicious domain details for go0gle.xyz:")
    print(f"  Reputation score: {data['reputation_score']}")
    print(f"  Status: {data['status']}")
    print(f"  Flags: {data['flags']}")
    assert data["status"] in ["danger", "suspicious"]
    print("[OK] Domain reputation endpoint test passed.")

    print("\n==============================================")
    print("All tests completed successfully!")
    print("==============================================")

if __name__ == "__main__":
    run_tests()
