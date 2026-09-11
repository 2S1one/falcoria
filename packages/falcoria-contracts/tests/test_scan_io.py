import pytest
from pydantic import ValidationError

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask


def test_scan_task_defaults() -> None:
    task = ScanTask(
        ip="10.0.0.1",
        open_ports_args="-p 22,80",
        timeout=30,
        mode=ImportMode.INSERT,
    )

    assert task.service_args is None
    assert task.hostnames == []


def test_scan_task_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValidationError):
        ScanTask(
            ip="10.0.0.1",
            open_ports_args="-p 22,80",
            timeout=0,
            mode=ImportMode.INSERT,
        )


def test_scan_batch_input_holds_tasks() -> None:
    task = ScanTask(
        ip="10.0.0.1",
        open_ports_args="-p 22,80",
        service_args="-sV",
        timeout=30,
        mode=ImportMode.REPLACE,
        hostnames=["host.example.com"],
    )
    batch = ScanBatchInput(project_id="proj-1", scan_id="scan-1", tasks=[task])

    assert batch.tasks == [task]


def test_scan_batch_result_accounts_totals() -> None:
    result = ScanBatchResult(total=10, completed=8, failed=2)

    assert result.completed + result.failed == result.total
