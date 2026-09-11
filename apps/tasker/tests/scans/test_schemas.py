import pytest
from pydantic import ValidationError

from falcoria_contracts.enums import PortProtocol
from falcoria_tasker.scans.schemas import OpenPortsOpts, ServiceOpts


def test_open_ports_opts_defaults() -> None:
    opts = OpenPortsOpts(ports=["22", "80"])

    assert opts.transport_protocol is PortProtocol.TCP
    assert opts.skip_host_discovery is True


@pytest.mark.parametrize("ports", [["0"], ["70000"], ["100-50"], ["abc"], ["22-x"]])
def test_open_ports_opts_rejects_invalid_ports(ports: list[str]) -> None:
    with pytest.raises(ValidationError):
        OpenPortsOpts(ports=ports)


def test_open_ports_opts_accepts_ranges() -> None:
    opts = OpenPortsOpts(ports=["22", "1000-2000"])

    assert opts.ports == ["22", "1000-2000"]


def test_service_opts_defaults() -> None:
    opts = ServiceOpts()

    assert opts.aggressive_scan is False
    assert opts.traceroute is False
