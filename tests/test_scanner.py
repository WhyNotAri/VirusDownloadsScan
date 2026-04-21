import hashlib
from types import SimpleNamespace

import pytest
import requests

import scanner


def response(status_code, payload=None, text=""):
    return SimpleNamespace(
        status_code=status_code,
        text=text,
        json=lambda: payload or {},
    )


def test_calculate_hash_returns_sha256(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    assert scanner.calculate_hash(str(sample)) == hashlib.sha256(b"abc").hexdigest()


def test_calculate_hash_missing_file_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "is_heavy_download", lambda *_: False)
    assert scanner.calculate_hash(str(tmp_path / "missing.bin")) is None


@pytest.mark.parametrize(
    ("status_code", "payload", "expected"),
    [
        (
            200,
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}},
            {"status": 200, "found": True, "stats": {"malicious": 1}},
        ),
        (404, None, {"status": 404, "found": False, "stats": None}),
        (500, None, {"status": 500, "error": "http_error_500"}),
    ],
)
def test_consult_hash_cases(monkeypatch, status_code, payload, expected):
    monkeypatch.setattr(
        scanner.requests,
        "get",
        lambda *_args, **_kwargs: response(status_code, payload, text="boom"),
    )
    assert scanner.consult_hash("hash") == expected


def test_consult_hash_request_exception(monkeypatch):
    monkeypatch.setattr(
        scanner.requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(requests.RequestException("network")),
    )
    assert scanner.consult_hash("hash") == {"status": False, "error": "request_failed"}


def test_scan_file_returns_error_without_upload(monkeypatch):
    monkeypatch.setattr(scanner, "calculate_hash", lambda *_: "hash")
    monkeypatch.setattr(scanner, "consult_hash", lambda *_: {"error": "request_failed"})
    upload_called = {"value": False}

    def fake_upload(*_args, **_kwargs):
        upload_called["value"] = True
        return {"status_code": 200}

    monkeypatch.setattr(scanner, "upload_file", fake_upload)

    assert scanner.scan_file("file.bin") == {"error": "request_failed"}
    assert upload_called["value"] is False


def test_scan_file_uploads_when_result_none(monkeypatch):
    monkeypatch.setattr(scanner, "calculate_hash", lambda *_: "hash")
    monkeypatch.setattr(scanner, "consult_hash", lambda *_: None)
    monkeypatch.setattr(scanner, "upload_file", lambda *_: {"status_code": 200})
    assert scanner.scan_file("file.bin") == {"upload_status": {"status_code": 200}}


def test_upload_file_success(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    monkeypatch.setattr(
        scanner.requests,
        "post",
        lambda *_args, **_kwargs: response(200, payload={"data": {"id": "123"}}),
    )
    assert scanner.upload_file(str(sample)) == {"status_code": 200, "data": {"data": {"id": "123"}}}


def test_upload_file_open_error_returns_none(monkeypatch):
    monkeypatch.setattr(
        "builtins.open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no file")),
    )
    assert scanner.upload_file("does-not-exist.bin") is None
