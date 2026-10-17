"""Tests for sending local files as attachments."""
import zipfile
from io import BytesIO

import pytest
from PIL import Image

JPEG_MAGIC = b"\xff\xd8"


@pytest.fixture
def text_file(tmp_path):
    path = tmp_path / "log.txt"
    path.write_bytes(b"line one\nline two\n")
    return path


@pytest.fixture
def png_file(tmp_path):
    path = tmp_path / "snapshot.png"
    Image.new("RGB", (200, 100), color="red").save(path, format="png")
    return path


def _sent_body(mock_put) -> bytes:
    return mock_put.call_args.kwargs["data"]


def test_attach_file_is_sent_unchanged(ntfy_service, mock_put, text_file):
    ntfy_service.send_message("hello", data={"attach_file": str(text_file)})

    assert _sent_body(mock_put) == text_file.read_bytes()


def test_compress_file_sends_zip_with_original_content(ntfy_service, mock_put, text_file):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(text_file), "attachment_compress_file": 5},
    )

    with zipfile.ZipFile(BytesIO(_sent_body(mock_put))) as archive:
        assert archive.namelist() == ["log.txt"]
        assert archive.read("log.txt") == text_file.read_bytes()


def test_compress_file_accepts_numeric_string(ntfy_service, mock_put, text_file):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(text_file), "attachment_compress_file": "5"},
    )

    assert zipfile.is_zipfile(BytesIO(_sent_body(mock_put)))


def test_compress_image_sends_jpeg(ntfy_service, mock_put, png_file):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(png_file), "attachment_compress_image": 50},
    )

    assert _sent_body(mock_put).startswith(JPEG_MAGIC)


def test_compress_image_accepts_numeric_string(ntfy_service, mock_put, png_file):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(png_file), "attachment_compress_image": "50"},
    )

    assert _sent_body(mock_put).startswith(JPEG_MAGIC)


@pytest.mark.parametrize(
    ("resize", "expected_size"),
    [("100px", (100, 50)), ("50%", (100, 50))],
)
def test_resize_image_keeps_aspect_ratio(ntfy_service, mock_put, png_file, resize, expected_size):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(png_file), "attachment_resize_image": resize},
    )

    with Image.open(BytesIO(_sent_body(mock_put))) as img:
        assert img.size == expected_size


@pytest.mark.parametrize(
    ("filename", "processing", "expected_filename"),
    [
        ("cam.png", {}, "cam.png"),
        ("cam.png", {"attachment_compress_image": 50}, "cam.jpg"),
        ("cam.png", {"attachment_resize_image": "50%"}, "cam.jpg"),
        ("cam.jpeg", {"attachment_compress_image": 50}, "cam.jpg"),
        ("cam.png", {"attachment_compress_file": 5}, "cam.zip"),
        ("cam.zip", {"attachment_compress_file": 5}, "cam.zip"),
        ("cam.png", {"attachment_resize_image": "50%", "attachment_compress_file": 5}, "cam.zip"),
        ("cam.png", {"attachment_compress_image": 50, "attachment_compress_file": 5}, "cam.jpg"),
    ],
)
def test_attachment_filename_matches_sent_content(ntfy_service, mock_put, png_file, filename, processing, expected_filename):
    ntfy_service.send_message(
        "hello",
        data={"attach_file": str(png_file), "attachment_filename": filename, **processing},
    )

    assert mock_put.call_args.kwargs["headers"]["Filename"] == expected_filename.encode("utf-8")
