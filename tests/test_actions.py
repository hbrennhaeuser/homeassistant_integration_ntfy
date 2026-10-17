"""Tests for ntfy action buttons."""
import pytest
from homeassistant.exceptions import ServiceValidationError


def _sent_actions(ntfy_service, mock_put, actions) -> str:
    ntfy_service.send_message("hello", data={"actions": actions})
    return mock_put.call_args.kwargs["headers"]["X-Actions"]


def test_view_action(ntfy_service, mock_put):
    actions = [{"action": "view", "label": "Open", "url": "https://example.com", "clear": True}]

    assert _sent_actions(ntfy_service, mock_put, actions) == "view, Open, https://example.com, clear=true"


def test_broadcast_action(ntfy_service, mock_put):
    actions = [{"action": "broadcast", "label": "Take photo", "intent": "io.heckel.ntfy.USER_ACTION",
                "extras": {"cmd": "pic"}}]

    assert _sent_actions(ntfy_service, mock_put, actions) == (
        "broadcast, Take photo, intent=io.heckel.ntfy.USER_ACTION, extras.cmd=pic"
    )


def test_http_action(ntfy_service, mock_put):
    actions = [{"action": "http", "label": "Close door", "url": "https://example.com/door",
                "method": "PUT", "headers": {"Authorization": "Bearer x"}, "body": "close"}]

    assert _sent_actions(ntfy_service, mock_put, actions) == (
        "http, Close door, https://example.com/door, method=PUT, headers.Authorization=Bearer x, body=close"
    )


def test_multiple_actions_are_joined(ntfy_service, mock_put):
    actions = [
        {"action": "view", "label": "A", "url": "https://example.com/a"},
        {"action": "view", "label": "B", "url": "https://example.com/b"},
    ]

    assert _sent_actions(ntfy_service, mock_put, actions) == (
        "view, A, https://example.com/a; view, B, https://example.com/b"
    )


@pytest.mark.parametrize(
    "action",
    [
        {"action": "unknown", "label": "x"},
        {"action": "view", "label": "missing url"},
        {"action": "http", "label": "x", "url": "https://example.com", "method": "PATCH"},
    ],
    ids=["unknown-type", "view-without-url", "http-invalid-method"],
)
def test_invalid_action_raises(ntfy_service, mock_put, action):
    with pytest.raises(ServiceValidationError):
        ntfy_service.send_message("hello", data={"actions": [action]})

    mock_put.assert_not_called()
