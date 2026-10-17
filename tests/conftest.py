"""Shared fixtures for the ntfy integration tests."""
from unittest.mock import MagicMock, patch

import pytest

from custom_components.ntfy.notify import NtfyNotificationService

BASE_CONFIG = {
    "topic": "test-topic",
    "url": "https://ntfy.example.com",
}


@pytest.fixture
def ntfy_service() -> NtfyNotificationService:
    """Return a service with a minimal valid configuration."""
    return NtfyNotificationService(dict(BASE_CONFIG))


@pytest.fixture
def mock_put() -> MagicMock:
    """Capture the HTTP request instead of sending it to a server."""
    with patch("custom_components.ntfy.notify.requests.put") as mocked_put:
        yield mocked_put
