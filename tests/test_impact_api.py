"""
Tests for the Impact Analysis API endpoints.

Tests cover:
- POST /api/impact/analyze
- GET /api/impact/status
- GET /api/impact/supported-interfaces
"""

import json
import sqlite3
import pytest
from unittest.mock import patch, MagicMock



def _clear_password_change_required():
    """Clear password_change_required flag via direct SQLite (see conftest.py for why)."""
    from dashboard.auth.config import DB_PATH
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE users SET password_change_required = 0 WHERE username = 'admin'")
        conn.commit()
        conn.close()
    except Exception:
        pass


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    # Patch the feature flag before importing the app
    with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
        mock_config.return_value = {
            "enabled": True,
            "supported_platforms": ["cisco_xe"],
            "analysis_timeout_sec": 10,
            "data_max_age_sec": 300,
            "rate_limit_per_user_per_minute": 10,
            "rate_limit_per_device_per_minute": 2,
        }

        from dashboard.api_server import app

        app.config["TESTING"] = True
        _clear_password_change_required()
        with app.test_client() as client:
            yield client


@pytest.fixture
def client_disabled():
    """Create a test client with feature disabled."""
    with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
        mock_config.return_value = {
            "enabled": False,
            "supported_platforms": ["cisco_xe"],
            "analysis_timeout_sec": 10,
            "data_max_age_sec": 300,
            "rate_limit_per_user_per_minute": 10,
            "rate_limit_per_device_per_minute": 2,
        }

        from dashboard.api_server import app

        app.config["TESTING"] = True
        _clear_password_change_required()
        with app.test_client() as client:
            yield client


@pytest.fixture
def auth_headers(client):
    """Get valid JWT auth headers by logging in via the test client."""
    response = client.post('/api/auth/login', json={
        'username': 'admin',
        'password': 'admin'
    })
    if response.status_code == 200:
        data = json.loads(response.data)
        token = data.get('access_token') or data.get('token')
        if token:
            return {'Authorization': f'Bearer {token}'}
    return {}


# =============================================================================
# GET /api/impact/status Tests
# =============================================================================


class TestImpactStatus:
    """Tests for GET /api/impact/status."""

    def test_returns_feature_status(self, client, auth_headers):
        """Should return feature configuration."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "supported_platforms": ["cisco_xe"],
                "analysis_timeout_sec": 10,
                "data_max_age_sec": 300,
                "rate_limit_per_user_per_minute": 10,
                "rate_limit_per_device_per_minute": 2,
            }

            response = client.get("/api/impact/status", headers=auth_headers)

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["enabled"] is True
            assert "cisco_xe" in data["supported_platforms"]
            assert data["analysis_timeout_sec"] == 10
            assert data["rate_limits"]["per_user_per_minute"] == 10


# =============================================================================
# GET /api/impact/supported-interfaces Tests
# =============================================================================


class TestSupportedInterfaces:
    """Tests for GET /api/impact/supported-interfaces."""

    def test_returns_supported_info(self, client, auth_headers):
        """Should return interface support information."""
        response = client.get("/api/impact/supported-interfaces",
                              headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "supported" in data
        assert "unsupported" in data
        assert "planned_phases" in data


# =============================================================================
# POST /api/impact/analyze Tests
# =============================================================================


class TestAnalyzeEndpoint:
    """Tests for POST /api/impact/analyze."""

    def test_returns_501_when_feature_disabled(self, client, auth_headers):
        """Should return 501 when feature is disabled."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {
                "enabled": False,
                "supported_platforms": ["cisco_xe"],
            }

            response = client.post(
                "/api/impact/analyze",
                json={
                    "device": "R1",
                    "interface": "GigabitEthernet1",
                    "command": "shutdown",
                },
                headers=auth_headers,
            )

            assert response.status_code == 501
            data = json.loads(response.data)
            assert data["status"] == "unsupported"
            assert "disabled" in data["reason"].lower()

    def test_returns_400_when_no_json(self, client, auth_headers):
        """Should return 400 when no JSON data provided."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {"enabled": True}

            response = client.post(
                "/api/impact/analyze",
                data="not json",
                content_type="text/plain",
                headers=auth_headers,
            )

            assert response.status_code == 400

    def test_returns_400_when_missing_required_fields(self, client, auth_headers):
        """Should return 400 when required fields are missing."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {"enabled": True}

            response = client.post(
                "/api/impact/analyze",
                json={"device": "R1"},  # Missing interface and command
                headers=auth_headers,
            )

            assert response.status_code == 400
            data = json.loads(response.data)
            assert "required" in data["reason"].lower()

    def test_successful_analysis(self, client, auth_headers):
        """Should return analysis result on success."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "supported_platforms": ["cisco_xe"],
                "analysis_timeout_sec": 10,
                "data_max_age_sec": 300,
                "rate_limit_per_user_per_minute": 10,
                "rate_limit_per_device_per_minute": 2,
            }

            with patch("config.readonly_credentials.get_readonly_credentials") as mock_creds:
                from config.readonly_credentials import StaticReadOnlyCredentials

                mock_creds.return_value = StaticReadOnlyCredentials(
                    username="readonly", password="readonly123"
                )

                with patch("core.impact_analyzer.ImpactAnalyzer") as mock_analyzer_class:
                    mock_analyzer = MagicMock()
                    mock_result = MagicMock()
                    mock_result.status.value = "completed"
                    mock_result.to_dict.return_value = {
                        "status": "completed",
                        "analysis_id": "ia-123456",
                        "device": "R1",
                        "interface": "GigabitEthernet1",
                        "command": "shutdown",
                        "risk_category": "MEDIUM",
                    }
                    mock_analyzer.analyze_sync.return_value = mock_result
                    mock_analyzer_class.return_value = mock_analyzer

                    response = client.post(
                        "/api/impact/analyze",
                        json={
                            "device": "R1",
                            "interface": "GigabitEthernet1",
                            "command": "shutdown",
                        },
                        headers=auth_headers,
                    )

                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert data["status"] == "completed"
                    assert data["device"] == "R1"

    def test_returns_429_on_rate_limit(self, client, auth_headers):
        """Should return 429 when rate limited."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "supported_platforms": ["cisco_xe"],
            }

            with patch("config.readonly_credentials.get_readonly_credentials") as mock_creds:
                from config.readonly_credentials import StaticReadOnlyCredentials

                mock_creds.return_value = StaticReadOnlyCredentials(
                    username="readonly", password="readonly123"
                )

                with patch("core.impact_analyzer.ImpactAnalyzer") as mock_analyzer_class:
                    mock_analyzer = MagicMock()
                    mock_result = MagicMock()
                    mock_result.status.value = "rate_limited"
                    mock_result.to_dict.return_value = {
                        "status": "rate_limited",
                        "reason": "Too many requests",
                    }
                    mock_analyzer.analyze_sync.return_value = mock_result
                    mock_analyzer_class.return_value = mock_analyzer

                    response = client.post(
                        "/api/impact/analyze",
                        json={
                            "device": "R1",
                            "interface": "GigabitEthernet1",
                            "command": "shutdown",
                        },
                        headers=auth_headers,
                    )

                    assert response.status_code == 429

    def test_returns_504_on_timeout(self, client, auth_headers):
        """Should return 504 on timeout."""
        with patch("core.feature_flags.get_impact_analysis_config") as mock_config:
            mock_config.return_value = {
                "enabled": True,
                "supported_platforms": ["cisco_xe"],
            }

            with patch("config.readonly_credentials.get_readonly_credentials") as mock_creds:
                from config.readonly_credentials import StaticReadOnlyCredentials

                mock_creds.return_value = StaticReadOnlyCredentials(
                    username="readonly", password="readonly123"
                )

                with patch("core.impact_analyzer.ImpactAnalyzer") as mock_analyzer_class:
                    mock_analyzer = MagicMock()
                    mock_result = MagicMock()
                    mock_result.status.value = "timeout"
                    mock_result.to_dict.return_value = {
                        "status": "timeout",
                        "reason": "Analysis timed out",
                    }
                    mock_analyzer.analyze_sync.return_value = mock_result
                    mock_analyzer_class.return_value = mock_analyzer

                    response = client.post(
                        "/api/impact/analyze",
                        json={
                            "device": "R1",
                            "interface": "GigabitEthernet1",
                            "command": "shutdown",
                        },
                        headers=auth_headers,
                    )

                    assert response.status_code == 504
