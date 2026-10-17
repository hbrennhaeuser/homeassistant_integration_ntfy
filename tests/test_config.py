"""Tests for the platform configuration documented in the readme."""
from base64 import b64encode

import pytest
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.ntfy.notify import NtfyNotificationService

from .conftest import BASE_CONFIG


def _sent_authorization(config, mock_put):
    NtfyNotificationService({**BASE_CONFIG, **config}).send_message("hello")
    return mock_put.call_args.kwargs["headers"]["Authorization"]


def test_no_authentication(mock_put):
    assert _sent_authorization({}, mock_put) is None


def test_token_authentication(mock_put):
    config = {"authentication": "token", "token": "tk_secret"}

    assert _sent_authorization(config, mock_put) == "Bearer tk_secret"


def test_user_pass_authentication(mock_put):
    config = {"authentication": "user-pass", "username": "user", "password": "pass"}

    assert _sent_authorization(config, mock_put) == "Basic " + b64encode(b"user:pass").decode()


@pytest.mark.parametrize(
    "config",
    [
        {"authentication": "token"},
        {"authentication": "user-pass", "username": "user"},
        {"authentication": "unknown"},
    ],
    ids=["token-without-token", "user-pass-without-password", "unknown-type"],
)
def test_incomplete_authentication_is_rejected(config):
    with pytest.raises(ServiceValidationError):
        NtfyNotificationService({**BASE_CONFIG, **config})


@pytest.mark.parametrize("config", [{"url": "not a url"}, {"attachment_maxsize": "10X"}])
def test_invalid_config_is_rejected(config):
    with pytest.raises(ServiceValidationError):
        NtfyNotificationService({**BASE_CONFIG, **config})


@pytest.mark.parametrize("maxsize", ["1K", "1024", "1024B"])
def test_attachment_maxsize_rejects_larger_files(mock_put, tmp_path, maxsize):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 2048)
    service = NtfyNotificationService({**BASE_CONFIG, "attachment_maxsize": maxsize})

    with pytest.raises(HomeAssistantError):
        service.send_message("hello", data={"attach_file": str(path)})

    mock_put.assert_not_called()


def test_attachment_maxsize_allows_smaller_files(mock_put, tmp_path):
    path = tmp_path / "small.bin"
    path.write_bytes(b"x" * 512)
    service = NtfyNotificationService({**BASE_CONFIG, "attachment_maxsize": "1K"})

    service.send_message("hello", data={"attach_file": str(path)})

    assert mock_put.call_args.kwargs["data"] == path.read_bytes()
