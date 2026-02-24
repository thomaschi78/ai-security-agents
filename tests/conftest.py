"""Pytest configuration and fixtures."""

import pytest
import asyncio
import sys
from pathlib import Path

# Add python source to path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_target():
    """Sample scan target for testing."""
    from results import ScanTarget

    return ScanTarget(
        url="http://testphp.vulnweb.com/search.php",
        parameters=[{"name": "searchFor", "value": "test"}],
        method="GET"
    )


@pytest.fixture
def mock_http_response():
    """Mock HTTP response with SQL error."""
    return {
        "status_code": 500,
        "headers": {"Content-Type": "text/html"},
        "body": "Error: You have an error in your SQL syntax near '' at line 1",
        "content_type": "text/html",
        "time_ms": 120.5
    }


@pytest.fixture
def mock_finding():
    """Mock vulnerability finding."""
    return {
        "id": "test-finding-001",
        "vulnerability_type": "sqli",
        "cweid": 89,
        "url": "http://example.com/search",
        "parameter": "q",
        "method": "GET",
        "confidence": 0.85,
        "stage": "CONFIRM",
        "indicators": ["SQL syntax error", "MySQL error"],
        "reasoning": ["Found error message indicating SQL injection"],
        "payload": "' OR '1'='1",
    }
