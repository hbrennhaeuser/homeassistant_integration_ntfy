"""Tests for sending plain notifications."""


def test_send_plain_message(ntfy_service, mock_put):
    ntfy_service.send_message("hello")

    mock_put.assert_called_once()
    request = mock_put.call_args.kwargs
    assert request["url"] == "https://ntfy.example.com/test-topic"
    assert request["headers"]["Message"] == b"hello"
    assert request["data"] is None
