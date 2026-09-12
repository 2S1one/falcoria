"""HTTP client for uploading scan reports to scanledger's import endpoint."""

from typing import Any

import httpx
from falcoria_http.transport import RetryingTransport

from falcoria_contracts.enums import ImportMode
from falcoria_worker.exceptions import ScanUploadError


class ScanledgerClient:
    """Thin wrapper over scanledger's scan-report import endpoint."""

    def __init__(
        self,
        base_url: str,
        service_token: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport if transport is not None else RetryingTransport(),
        )
        self._service_token = service_token

    async def aclose(self) -> None:
        """Closes the underlying HTTP connection pool."""
        await self._client.aclose()

    async def upload_report(
        self, project_id: str, scan_id: str, mode: ImportMode, xml: str
    ) -> dict[str, Any]:
        """Uploads an nmap XML report for `project_id`, tagged with `scan_id`.

        Raises:
            ScanUploadError: scanledger rejected or failed to process the report.
        """
        response = await self._client.post(
            f"/projects/{project_id}/ips/import",
            params={"mode": mode.value, "scan_id": scan_id},
            files={"report": ("report.xml", xml, "text/xml")},
            headers={"Authorization": f"Bearer {self._service_token}"},
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ScanUploadError(
                f"scanledger rejected the report for project {project_id}: "
                f"{response.status_code} {response.text}"
            ) from exc
        return response.json()
