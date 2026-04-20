import hashlib
import requests
import scanner


class _Response:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_calculate_hash_returns_sha256(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    expected = hashlib.sha256(b"abc").hexdigest()
    assert scanner.calculate_hash(str(sample)) == expected


def test_calculate_hash_missing_file_returns_none(tmp_path):
    missing = tmp_path / "missing.bin"
    assert scanner.calculate_hash(str(missing)) is None


def test_consult_hash_returns_found_stats(monkeypatch):
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "undetected": 69}
            }
        }
    }

    def fake_get(*args, **kwargs):
        return _Response(200, payload=payload)

    monkeypatch.setattr(scanner.requests, "get", fake_get)
    result = scanner.consult_hash("hash")

    assert result == {
        "status": 200,
        "found": True,
        "stats": {"malicious": 1, "undetected": 69},
    }


def test_consult_hash_returns_not_found(monkeypatch):
    def fake_get(*args, **kwargs):
        return _Response(404)

    monkeypatch.setattr(scanner.requests, "get", fake_get)
    result = scanner.consult_hash("hash")

    assert result == {"status": 404, "found": False, "stats": None}


def test_consult_hash_returns_http_error(monkeypatch):
    def fake_get(*args, **kwargs):
        return _Response(500, text="boom")

    monkeypatch.setattr(scanner.requests, "get", fake_get)
    result = scanner.consult_hash("hash")

    assert result == {"status": 500, "error": "http_error_500"}


def test_consult_hash_request_exception(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.RequestException("network down")

    monkeypatch.setattr(scanner.requests, "get", fake_get)
    result = scanner.consult_hash("hash")

    assert result == {"status": False, "error": "request_failed"}


def test_scan_file_returns_error_without_upload(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    monkeypatch.setattr(scanner, "consult_hash", lambda *_: {"error": "request_failed"})
    upload_called = False

    def fake_upload(*args, **kwargs):
        nonlocal upload_called
        upload_called = True
        return {"status_code": 200}

    monkeypatch.setattr(scanner, "upload_file", fake_upload)
    result = scanner.scan_file(str(sample))

    assert result == {"error": "request_failed"}
    assert upload_called is False


def test_scan_file_uploads_when_result_none(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    monkeypatch.setattr(scanner, "consult_hash", lambda *_: None)
    monkeypatch.setattr(scanner, "upload_file", lambda *_: {"status_code": 200})

    result = scanner.scan_file(str(sample))

    assert result == {"upload_status": {"status_code": 200}}
