"""Tests for scanledger.py — ScanledgerClient, mirroring tasker's own test pattern."""

from typing import Any

import httpx
import pytest

from falcoria_contracts.enums import ImportMode
from falcoria_worker.exceptions import ScanUploadError
from falcoria_worker.scanledger import ScanledgerClient

pytestmark = pytest.mark.anyio


def _client(handler: Any) -> ScanledgerClient:
    return ScanledgerClient(
        "http://scanledger.test/api", "worker-token", transport=httpx.MockTransport(handler)
    )


async def test_upload_report_posts_multipart_report_with_expected_params() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/projects/proj-1/ips/import"
        assert request.url.params["mode"] == "insert"
        assert request.url.params["scan_id"] == "scan-1"
        assert request.headers["authorization"] == "Bearer worker-token"
        assert b'name="report"' in request.content
        return httpx.Response(201, json={"updated": 1})

    client = _client(handler)
    result = await client.upload_report("proj-1", "scan-1", ImportMode.INSERT, "<xml/>")
    assert result == {"updated": 1}


async def test_upload_report_raises_scan_upload_error_on_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad report")

    client = _client(handler)
    with pytest.raises(ScanUploadError, match="bad report"):
        await client.upload_report("proj-1", "scan-1", ImportMode.INSERT, "<xml/>")
