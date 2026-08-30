"""
Security tests for the claims made in Section 4.6.

Run from the project root:   python -m pytest tests/test_security.py -v

Each test maps to a specific non-functional requirement so the results can
be reported directly against NFR5 to NFR9 in the evaluation chapter.
"""

import io
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as scanner

ORIGINAL_VIRUSTOTAL = scanner.check_virustotal_domain


@pytest.fixture(autouse=True)
def no_virustotal(monkeypatch):
    monkeypatch.setattr(scanner, "check_virustotal_domain", lambda domain: (0, ""))


@pytest.fixture
def client():
    scanner.app.config["TESTING"] = True
    with scanner.app.test_client() as c:
        yield c


# --------------------------------------------------------------------------
# NFR6 — upload size ceiling
# --------------------------------------------------------------------------

def test_oversized_upload_is_rejected(client):
    """A file over 5 MB must be refused with 413, not a stack trace."""
    payload = b"A" * (6 * 1024 * 1024)
    data = {"file": (io.BytesIO(payload), "huge.eml")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 413
    assert b"Traceback" not in response.data


def test_size_limit_is_five_megabytes():
    assert scanner.app.config["MAX_CONTENT_LENGTH"] == 5 * 1024 * 1024


def test_upload_just_under_limit_is_accepted(client):
    payload = b"Subject: test\r\n\r\n" + (b"A" * (4 * 1024 * 1024))
    data = {"file": (io.BytesIO(payload), "large.eml")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200


# --------------------------------------------------------------------------
# NFR5 / NFR7 — extension whitelist, path traversal, in-memory processing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "payload.exe", "script.js", "archive.zip", "image.png", "noextension",
])
def test_disallowed_extensions_are_refused(client, filename):
    data = {"file": (io.BytesIO(b"content"), filename)}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 400


def test_path_traversal_filename_is_neutralised(client):
    """A traversal filename must not reach the filesystem or crash the app."""
    data = {"file": (io.BytesIO(b"Subject: hi\r\n\r\nbody"),
                     "../../../../etc/passwd.eml")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code in (200, 400)
    assert b"Traceback" not in response.data


def test_no_files_written_to_disk(client, tmp_path, monkeypatch):
    """NFR5: uploads are processed in memory only."""
    monkeypatch.chdir(tmp_path)
    before = set(os.listdir(tmp_path))
    data = {"file": (io.BytesIO(b"Subject: hi\r\n\r\nbody"), "message.eml")}
    client.post("/", data=data, content_type="multipart/form-data")
    assert set(os.listdir(tmp_path)) == before


# --------------------------------------------------------------------------
# NFR7 — malformed input handling
# --------------------------------------------------------------------------

def test_invalid_utf8_bytes_do_not_crash(client):
    """Corrupt byte sequences must decode without raising."""
    data = {"file": (io.BytesIO(b"Subject: \xff\xfe\x00broken\r\n\r\n\x80\x81"),
                     "corrupt.eml")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200


def test_empty_file_is_handled(client):
    data = {"file": (io.BytesIO(b""), "empty.eml")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code in (200, 400)
    assert b"Traceback" not in response.data


def test_malformed_json_does_not_raise(client):
    response = client.post("/scan", data="{not valid json",
                           content_type="application/json")
    assert response.status_code == 200


def test_missing_json_fields_default_safely(client):
    response = client.post("/scan", json={})
    assert response.status_code == 200
    assert response.get_json()["score"] == 0


def test_null_values_do_not_raise(client):
    response = client.post("/scan", json={
        "sender_domain": None, "email_text": None, "return_domain": None,
    })
    assert response.status_code == 200


# --------------------------------------------------------------------------
# NFR7 — output escaping
# --------------------------------------------------------------------------

def test_submitted_script_is_escaped_in_output(client):
    """User input echoed back must not render as live markup."""
    payload = "<script>alert('xss')</script> urgent"
    response = client.post("/", data={
        "sender_domain": "example-sender.net", "email_text": payload,
    })
    assert b"<script>alert" not in response.data


def test_domain_with_markup_is_escaped(client):
    response = client.post("/", data={
        "sender_domain": "<img src=x onerror=alert(1)>.com",
        "email_text": "urgent click here",
    })
    assert b"<img src=x onerror" not in response.data


# --------------------------------------------------------------------------
# 4.6.3 — regular expression injection and ReDoS
# --------------------------------------------------------------------------

def test_regex_metacharacters_are_escaped(monkeypatch):
    """A rule containing regex syntax must be matched literally."""
    hostile = {"a+b*(c": "crafted rule"}
    monkeypatch.setattr(scanner, "load_words_from_db",
                        lambda: (hostile, {}, ["tudublin.ie"], {}))

    # The literal string matches; a regex interpretation would not.
    literal = scanner.analyse("example-sender.net", "value a+b*(c here")
    assert any(f["category"] == "bad_word" for f in literal["findings"])

    # A string that only matches if the rule were treated as a pattern.
    as_pattern = scanner.analyse("example-sender.net", "value abbbcc here")
    assert not any(f["category"] == "bad_word" for f in as_pattern["findings"])


def test_catastrophic_backtracking_pattern_is_safe(monkeypatch):
    """A classic ReDoS rule must not cause exponential runtime."""
    hostile = {"(a+)+$": "ReDoS attempt"}
    monkeypatch.setattr(scanner, "load_words_from_db",
                        lambda: (hostile, {}, ["tudublin.ie"], {}))

    start = time.perf_counter()
    scanner.analyse("example-sender.net", "a" * 3000 + "!")
    assert time.perf_counter() - start < 2.0


def test_full_ruleset_completes_quickly():
    """NFR3: all rules over a realistic message without perceptible delay."""
    text = "Please click here to verify your account urgently. " * 40
    start = time.perf_counter()
    scanner.analyse("example-sender.net", text)
    assert time.perf_counter() - start < 2.0


# --------------------------------------------------------------------------
# NFR8 / NFR9 — credentials and external service failure
# --------------------------------------------------------------------------

def test_api_key_not_hardcoded():
    """NFR8: the credential must come from the environment, not the source."""
    with open(scanner.__file__, encoding="utf-8", errors="ignore") as handle:
        source = handle.read()
    assert "VT_API_KEY" in source
    assert "os.environ.get" in source or "os.getenv" in source


def test_missing_api_key_returns_no_score(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    score, _reason = ORIGINAL_VIRUSTOTAL("example.com")
    assert score == 0


def test_network_failure_returns_no_score(monkeypatch):
    """NFR9: an unreachable service must degrade, not raise."""
    def boom(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(scanner.urllib.request, "urlopen", boom)
    score, _reason = ORIGINAL_VIRUSTOTAL("example.com")
    assert score == 0


def test_verdict_still_produced_when_lookup_fails(monkeypatch):
    def boom(domain):
        return (0, "")

    monkeypatch.setattr(scanner, "check_virustotal_domain", boom)
    result = scanner.analyse("unknown-domain-xyz.com", "urgent click here")
    assert result["colour"] in ("GREEN", "ORANGE", "RED")


# --------------------------------------------------------------------------
# 4.7.3 — SQL injection in rule management
# --------------------------------------------------------------------------

def test_sql_injection_in_scan_input_is_inert(client):
    """Detection input reaches no SQL statement."""
    response = client.post("/scan", json={
        "sender_domain": "'; DROP TABLE bad_words; --",
        "email_text": "' OR '1'='1",
    })
    assert response.status_code == 200
    _bw, _bl, whitelist, _ba = scanner.load_words_from_db()
    assert len(whitelist) > 0  # tables intact