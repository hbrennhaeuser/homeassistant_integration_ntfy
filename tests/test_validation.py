"""Tests for validating the service call data."""
import pytest
from homeassistant.exceptions import ServiceValidationError


def test_existing_attach_file_passes(ntfy_service, tmp_path):
    path = tmp_path / "log.txt"
    path.write_text("content")

    ntfy_service._validate_message_params({"attach_file": str(path)})


def test_missing_attach_file_raises(ntfy_service, tmp_path):
    with pytest.raises(ServiceValidationError):
        ntfy_service._validate_message_params({"attach_file": str(tmp_path / "missing.txt")})


@pytest.mark.parametrize(
    ("data", "field"),
    [
        ({"attach_file": "/nonexistent/file.txt"}, "attach_file"),
        ({"priority": "very-high"}, "priority"),
        ({"click": "not a url"}, "click"),
    ],
)
def test_validation_error_names_the_invalid_field(ntfy_service, data, field):
    with pytest.raises(ServiceValidationError) as excinfo:
        ntfy_service._validate_message_params(data)

    assert field in str(excinfo.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [("attachment_compress_image", 101), ("attachment_compress_file", 10)],
)
def test_out_of_range_compression_level_raises(ntfy_service, tmp_path, field, value):
    path = tmp_path / "log.txt"
    path.write_text("content")

    with pytest.raises(ServiceValidationError):
        ntfy_service._validate_message_params({"attach_file": str(path), field: value})
