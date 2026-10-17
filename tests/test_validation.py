"""Tests for validating the service call data."""
import pytest
from homeassistant.exceptions import ServiceValidationError


@pytest.fixture
def text_file(tmp_path):
    path = tmp_path / "log.txt"
    path.write_text("content")
    return path


def test_missing_attach_file_raises(ntfy_service, mock_put, tmp_path):
    with pytest.raises(ServiceValidationError):
        ntfy_service.send_message("hello", data={"attach_file": str(tmp_path / "missing.txt")})

    mock_put.assert_not_called()


@pytest.mark.parametrize(
    ("data", "field"),
    [
        ({"attach_file": "/nonexistent/file.txt"}, "attach_file"),
        ({"priority": "very-high"}, "priority"),
        ({"click": "not a url"}, "click"),
        ({"unknown_option": "x"}, "unknown_option"),
    ],
)
def test_validation_error_names_the_invalid_field(ntfy_service, mock_put, data, field):
    with pytest.raises(ServiceValidationError) as excinfo:
        ntfy_service.send_message("hello", data=data)

    assert field in str(excinfo.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [("attachment_compress_image", 101), ("attachment_compress_file", 10)],
)
def test_out_of_range_compression_level_raises(ntfy_service, mock_put, text_file, field, value):
    with pytest.raises(ServiceValidationError):
        ntfy_service.send_message("hello", data={"attach_file": str(text_file), field: value})


@pytest.mark.parametrize(
    "data",
    [
        {"attach_url": "https://example.com/a.jpg", "attach_file": "FILE"},
        {"attachment_filename": "a.txt"},
        {"attachment_compress_file": 5},
        {"attachment_compress_image": 50},
        {"attachment_resize_image": "50%"},
        {"attach_file": "FILE", "attachment_compress_image": 50},
    ],
    ids=["url-and-file", "filename-without-attachment", "compress-file-without-file",
         "compress-image-without-file", "resize-without-file", "compress-image-on-non-image"],
)
def test_invalid_option_combinations_raise(ntfy_service, mock_put, text_file, data):
    data = {key: str(text_file) if value == "FILE" else value for key, value in data.items()}

    with pytest.raises(ServiceValidationError):
        ntfy_service.send_message("hello", data=data)

    mock_put.assert_not_called()


def test_topic_override_rejected_by_default(ntfy_service, mock_put):
    with pytest.raises(ServiceValidationError):
        ntfy_service.send_message("hello", data={"topic": "other"})
