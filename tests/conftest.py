"""Shared pytest fixtures for NetworkOps tests."""
import os
import shutil
import sys
import time
import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, MagicMock

# Add project root to path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Deterministic test environment — set BEFORE any dashboard module imports.
# In CI, there is no .env file, so JWT secrets fall back to random values
# and SINGLE_SESSION_ENABLED defaults to true. Both cause 401s in tests:
#   - Random JWT secrets can differ between Pydantic instantiations
#   - Single-session validation rejects tokens if sessions aren't registered
# ---------------------------------------------------------------------------
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret-for-pytest-32chars!')
os.environ.setdefault('JWT_REFRESH_SECRET', 'test-refresh-secret-for-pytest!!')
os.environ.setdefault('SINGLE_SESSION_ENABLED', 'false')


# =============================================================================
# Database Fixtures (consolidated DB)
# =============================================================================

@pytest.fixture(autouse=True)
def _reset_db_singletons():
    """Reset all DB-related singletons between tests for isolation."""
    yield
    # Teardown: reset singletons so next test starts clean
    from core.db import DatabaseManager
    DatabaseManager.reset()
    from core.unified_db import UnifiedDB
    with UnifiedDB._lock:
        UnifiedDB._instance = None


@pytest.fixture(scope="session")
def _template_db(tmp_path_factory):
    """Run Alembic migrations once per session to create a template DB.

    Other fixtures copy this template instead of re-running migrations,
    making per-test DB setup fast (~1ms copy vs ~200ms migration).
    """
    template_dir = tmp_path_factory.mktemp("template")
    template_path = template_dir / "template.db"

    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config(os.path.join(_PROJECT_ROOT, "alembic.ini"))
    alembic_cfg.set_main_option(
        "sqlalchemy.url", f"sqlite:///{template_path}"
    )
    alembic_cfg.set_main_option(
        "script_location", os.path.join(_PROJECT_ROOT, "alembic")
    )
    command.upgrade(alembic_cfg, "head")

    return template_path


@pytest.fixture
def consolidated_db(tmp_path, _template_db):
    """Per-test consolidated DB: copy the template and wire up DatabaseManager.

    Yields the temp DB path.  All modules that use DatabaseManager
    (UnifiedDB, AgentDatabase, auth, quota, sessions, mfa, etc.)
    will read/write this temp DB.
    """
    db_path = tmp_path / "test_networkops.db"
    shutil.copy2(_template_db, db_path)

    from core.db import DatabaseManager
    DatabaseManager.reset()
    dm = DatabaseManager.get_instance(db_path=db_path)

    yield db_path

    # teardown handled by autouse _reset_db_singletons


# =============================================================================
# Existing Fixtures
# =============================================================================

@pytest.fixture
def api_base():
    """Return API base URL from environment or default."""
    return os.getenv("API_BASE", "http://localhost:5001")


@pytest.fixture
def requires_devices():
    """Skip test if SKIP_DEVICE_TESTS is set."""
    if os.getenv("SKIP_DEVICE_TESTS"):
        pytest.skip("Skipping device tests (SKIP_DEVICE_TESTS is set)")


@pytest.fixture
def test_device():
    """Return a test device name."""
    return os.getenv("TEST_DEVICE", "R1")


# =============================================================================
# MCP Tools Test Fixtures
# =============================================================================

@pytest.fixture
def mock_devices():
    """Fake network device inventory for tests."""
    return {
        "R1": {"hostname": "192.0.2.1", "device_type": "cisco_xe"},
        "R2": {"hostname": "192.0.2.2", "device_type": "cisco_xe"},
        "R3": {"hostname": "192.0.2.3", "device_type": "cisco_xe"},
        "Alpine-1": {"hostname": "192.0.2.10", "device_type": "linux"},
    }


@pytest.fixture
def mock_scrapli_device():
    """Provide a mock async connection context (simulating Scrapli)."""
    conn = AsyncMock()
    conn.__aenter__.return_value = conn
    conn.__aexit__.return_value = None
    conn.send_command.return_value = SimpleNamespace(result="MOCK_COMMAND_RESULT")
    conn.send_configs.return_value = SimpleNamespace(result="MOCK_CONFIG_RESULT")
    return conn


@pytest.fixture
def mock_device_cache():
    """Mock the device cache for health checks."""
    cache = AsyncMock()
    cache.get_health.return_value = None  # Cache miss by default
    cache.get_health_batch.return_value = {}
    cache.set_health.return_value = None
    return cache


@pytest.fixture
def patch_mcp_device_imports(mock_devices, mock_scrapli_device, mock_device_cache):
    """
    Patch device-related symbols in mcp_tools.device for isolated testing.

    This fixture patches:
    - DEVICES dict
    - get_scrapli_device factory
    - get_ios_xe_connection
    - get_linux_connection
    - get_device_cache
    - run_containerlab_command
    - log_event (to suppress logging)
    """
    with patch("mcp_tools.device.DEVICES", mock_devices), \
         patch("mcp_tools.device.get_scrapli_device", return_value=mock_devices.get("R1", {})), \
         patch("mcp_tools.device.get_ios_xe_connection", return_value=mock_scrapli_device), \
         patch("mcp_tools.device.get_linux_connection", return_value=mock_scrapli_device), \
         patch("mcp_tools.device.get_device_cache", return_value=mock_device_cache), \
         patch("mcp_tools.device.run_containerlab_command", return_value="MOCK_CONTAINERLAB"), \
         patch("mcp_tools.device.log_event", return_value=None):
        yield


@pytest.fixture
def timed_run():
    """Utility fixture to measure duration of async test sections."""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.perf_counter()

        def stop(self):
            self.end_time = time.perf_counter()

        @property
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

    return Timer()


@pytest.fixture(autouse=False)
def reset_semaphore():
    """Reset the shared semaphore between tests."""
    from mcp_tools._shared import reset_semaphore
    reset_semaphore()
    yield
    reset_semaphore()


# =============================================================================
# Flask API Test Client Fixtures
# =============================================================================

@pytest.fixture
def app(consolidated_db):
    """Create Flask app for testing via the application factory.

    Depends on consolidated_db so that DatabaseManager is wired to a temp DB
    with all 41 tables (created by Alembic) before the Flask app starts.
    """
    from dashboard.app import create_app

    flask_app = create_app(config={
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
    })

    # Clear password_change_required for the admin user so tests get
    # unrestricted tokens.  Auth now uses the consolidated DatabaseManager,
    # so we write directly to its DB (not the legacy users.db path).
    try:
        from core.db import DatabaseManager
        conn = DatabaseManager.get_instance().get_connection()
        conn.execute("UPDATE users SET password_change_required = 0 WHERE username = 'admin'")
        conn.commit()
        DatabaseManager.get_instance().release_connection(conn)
    except Exception:
        pass

    return flask_app


@pytest.fixture
def client(app):
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Get valid JWT auth headers by logging in via the same test client."""
    response = client.post('/api/auth/login', json={
        'username': 'admin',
        'password': 'admin',
    })
    if response.status_code == 200:
        data = response.get_json()
        token = data.get('access_token') or data.get('token')
        if token:
            return {'Authorization': f'Bearer {token}'}
    return {}
