"""Tests for sending plain notifications."""
from custom_components.ntfy.notify import NtfyNotificationService

from .conftest import BASE_CONFIG


def _sent_headers(mock_put) -> dict:
    return mock_put.call_args.kwargs["headers"]


def test_send_plain_message(ntfy_service, mock_put):
    ntfy_service.send_message("hello")

    mock_put.assert_called_once()
    request = mock_put.call_args.kwargs
    assert request["url"] == "https://ntfy.example.com/test-topic"
    assert request["headers"]["Message"] == b"hello"
    assert request["data"] is None


def test_optional_fields_are_sent_as_headers(ntfy_service, mock_put):
    ntfy_service.send_message(
        "hello",
        title="Garden",
        data={"tags": "warning,camera", "priority": "high", "click": "https://example.com/cam"},
    )

    headers = _sent_headers(mock_put)
    assert headers["Title"] == b"Garden"
    assert headers["Tags"] == "warning,camera"
    assert headers["Priority"] == "high"
    assert headers["Click"] == b"https://example.com/cam"


def test_newlines_are_escaped_for_the_header(ntfy_service, mock_put):
    ntfy_service.send_message("line one\r\nline two\nline three")

    assert _sent_headers(mock_put)["Message"] == b"line one\\nline two\\nline three"


def test_attach_url_is_sent_as_header(ntfy_service, mock_put):
    ntfy_service.send_message(
        "hello",
        data={"attach_url": "https://example.com/a.jpg", "attachment_filename": "a.jpg"},
    )

    headers = _sent_headers(mock_put)
    assert headers["Attach"] == b"https://example.com/a.jpg"
    assert headers["Filename"] == b"a.jpg"
    assert mock_put.call_args.kwargs["data"] is None


def test_topic_override_when_allowed(mock_put):
    service = NtfyNotificationService({**BASE_CONFIG, "allow_topic_override": True})

    service.send_message("hello", data={"topic": "other topic"})

    assert mock_put.call_args.kwargs["url"] == "https://ntfy.example.com/other%20topic"
