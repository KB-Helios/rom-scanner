"""Tests for scanner/threat_feed.py."""

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.threat_feed import fetch_threat_feed, update_if_stale


def _make_mock_response(body: bytes, etag: str = ""):
    resp = MagicMock()
    resp.read.return_value = body
    resp.headers = {"ETag": etag} if etag else {}
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


VALID_FEED = json.dumps({
    "sha256": {"abc123" + "0" * 58: "Test threat"},
    "md5": {},
}).encode()


def test_fetch_writes_atomically(tmp_path):
    dest = tmp_path / "threat_db.json"
    mock_resp = _make_mock_response(VALID_FEED, etag='"v1"')

    with patch("urllib.request.urlopen", return_value=mock_resp):
        new_etag = fetch_threat_feed("https://example.com/feed.json", dest)

    assert dest.exists()
    data = json.loads(dest.read_text())
    assert "sha256" in data
    assert new_etag == '"v1"'


def test_fetch_304_not_modified_returns_old_etag(tmp_path):
    dest = tmp_path / "threat_db.json"
    dest.write_text(json.dumps({"sha256": {}, "md5": {}}))

    def raise_304(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="https://example.com",
            code=304,
            msg="Not Modified",
            hdrs=MagicMock(),
            fp=MagicMock(),
        )

    with patch("urllib.request.urlopen", side_effect=raise_304):
        returned_etag = fetch_threat_feed(
            "https://example.com/feed.json", dest, etag='"old"'
        )

    assert returned_etag == '"old"'
    # File unchanged
    assert dest.exists()


def test_fetch_invalid_json_raises(tmp_path):
    dest = tmp_path / "threat_db.json"
    mock_resp = _make_mock_response(b"this is not json")

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(ValueError, match="not valid JSON"):
            fetch_threat_feed("https://example.com/feed.json", dest)


def test_update_if_stale_no_url_skips(pipeline_home: Path):
    cfg = {"scan": {"threat_feed_url": ""}}
    updated = update_if_stale(pipeline_home, cfg)
    assert updated is False


def test_update_if_stale_fetches_when_forced(pipeline_home: Path, tmp_path):
    feed_dest = pipeline_home / "threat_db.json"
    mock_resp = _make_mock_response(VALID_FEED, etag='"v2"')
    cfg = {
        "scan": {
            "threat_feed_url": "https://example.com/feed.json",
            "threat_feed_interval_hours": 24,
            "threat_feed_last_check": "2020-01-01T00:00:00+00:00",
            "threat_db_path": str(feed_dest),
        }
    }
    with patch("urllib.request.urlopen", return_value=mock_resp):
        updated = update_if_stale(pipeline_home, cfg, force=True)

    assert updated is True
    assert feed_dest.exists()
