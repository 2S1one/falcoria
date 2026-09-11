from dataclasses import dataclass

import aiodns
import pytest

from falcoria_tasker.scans.resolve import resolve_targets

pytestmark = pytest.mark.anyio


@dataclass
class _FakeRecord:
    host: str


class _FakeResolver:
    """A fake aiodns.DNSResolver: hostname -> successive per-attempt IP lists, or an Exception."""

    def __init__(self, responses: dict[str, list[list[str]] | Exception]) -> None:
        self._responses = responses
        self.calls: dict[str, int] = {}

    async def query(self, hostname: str, record_type: str) -> list[_FakeRecord]:
        assert record_type == "A"
        attempt = self.calls.get(hostname, 0)
        self.calls[hostname] = attempt + 1
        response = self._responses[hostname]
        if isinstance(response, Exception):
            raise response
        ips = response[min(attempt, len(response) - 1)]
        return [_FakeRecord(host=ip) for ip in ips]


def _patch_resolver(
    monkeypatch: pytest.MonkeyPatch, responses: dict[str, list[list[str]] | Exception]
) -> None:
    resolver = _FakeResolver(responses)
    monkeypatch.setattr("falcoria_tasker.scans.resolve.get_dns_resolver", lambda: resolver)


async def test_resolves_public_and_private_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(
        monkeypatch,
        {"public.example.com": [["8.8.8.8"]], "private.example.com": [["10.0.0.1"]]},
    )

    result = await resolve_targets(
        ["public.example.com", "private.example.com"], single_resolve=False, semaphore_limit=10
    )

    assert result.public_ips == ["8.8.8.8"]
    assert result.private_ips == {"10.0.0.1": ["private.example.com"]}
    assert result.unresolvable == []


async def test_single_resolve_keeps_only_first_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, {"multi.example.com": [["8.8.8.8", "8.8.4.4"]]})

    result = await resolve_targets(["multi.example.com"], single_resolve=True, semaphore_limit=10)

    assert result.public_ips == ["8.8.8.8"]


async def test_retries_before_succeeding(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, {"flaky.example.com": [[], ["8.8.8.8"]]})

    result = await resolve_targets(
        ["flaky.example.com"],
        single_resolve=False,
        semaphore_limit=10,
        retries=2,
        retry_delay_seconds=0,
    )

    assert result.public_ips == ["8.8.8.8"]
    assert result.unresolvable == []


async def test_marks_unresolvable_after_exhausting_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, {"dead.example.com": aiodns.error.DNSError("not found")})

    result = await resolve_targets(
        ["dead.example.com"],
        single_resolve=False,
        semaphore_limit=10,
        retries=2,
        retry_delay_seconds=0,
    )

    assert result.unresolvable == ["dead.example.com"]
    assert result.public_ips == []
    assert result.private_ips == {}


async def test_merges_sources_for_the_same_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, {"a.example.com": [["10.0.0.1"]], "b.example.com": [["10.0.0.1"]]})

    result = await resolve_targets(
        ["a.example.com", "b.example.com"], single_resolve=False, semaphore_limit=10
    )

    assert sorted(result.private_ips["10.0.0.1"]) == ["a.example.com", "b.example.com"]
