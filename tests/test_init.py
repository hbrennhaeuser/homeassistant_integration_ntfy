"""End-to-end tests through a Home Assistant instance and the notify service."""
import pytest
from homeassistant.setup import async_setup_component

PLATFORM_CONFIG = {
    "platform": "ntfy",
    "name": "ntfy_test",
    "topic": "test-topic",
    "url": "https://ntfy.example.com",
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


async def _setup_notify(hass, platform_config):
    assert await async_setup_component(hass, "notify", {"notify": [platform_config]})
    await hass.async_block_till_done()


async def test_service_call_sends_notification(hass, mock_put):
    await _setup_notify(hass, PLATFORM_CONFIG)

    await hass.services.async_call(
        "notify",
        "ntfy_test",
        {"message": "hello", "title": "Garden", "data": {"priority": "high", "tags": "camera"}},
        blocking=True,
    )

    request = mock_put.call_args.kwargs
    assert request["url"] == "https://ntfy.example.com/test-topic"
    assert request["headers"]["Message"] == b"hello"
    assert request["headers"]["Title"] == b"Garden"
    assert request["headers"]["Priority"] == "high"


async def test_service_call_with_attachment(hass, mock_put, tmp_path):
    path = tmp_path / "log.txt"
    path.write_bytes(b"content")
    await _setup_notify(hass, PLATFORM_CONFIG)

    await hass.services.async_call(
        "notify",
        "ntfy_test",
        {"message": "hello", "data": {"attach_file": str(path), "attachment_compress_file": "5"}},
        blocking=True,
    )

    assert mock_put.call_args.kwargs["data"].startswith(b"PK")


async def test_invalid_config_registers_no_service(hass, mock_put):
    await _setup_notify(hass, {**PLATFORM_CONFIG, "url": "not a url"})

    assert not hass.services.has_service("notify", "ntfy_test")
