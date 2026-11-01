from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_homepage_serves_product_ui():
    response = client.get("/")
    assert response.status_code == 200
    assert "SunoSafe" in response.text
    assert "Evidence, not vibes." in response.text


def test_health_does_not_expose_secret():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["app"] == "SunoSafe"
    assert "GNANI_API_KEY" not in response.text


def test_text_analysis_endpoint_returns_explainable_signals():
    response = client.post("/api/analyze-text", json={"transcript": "Apna OTP bataiye, warna account block ho jayega."})
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "text_analysis"
    assert data["transcript"].startswith("Apna OTP")
    assert any(item["id"] == "secret_credentials" for item in data["findings"])


def test_short_or_missing_text_is_rejected():
    response = client.post("/api/analyze-text", json={"transcript": ""})
    assert response.status_code == 422


def test_unsupported_upload_is_rejected_before_provider_call():
    response = client.post(
        "/api/analyze-audio",
        files={"audio": ("notes.txt", b"not audio", "text/plain")},
    )
    assert response.status_code == 415
