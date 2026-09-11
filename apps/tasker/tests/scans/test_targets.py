from falcoria_tasker.scans.targets import (
    expand_cidr,
    is_public_ip,
    partition_targets,
    remove_duplicates,
)


def test_is_public_ip_rejects_private_and_invalid() -> None:
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("not-an-ip") is False


def test_expand_cidr_slash_32_returns_single_ip() -> None:
    assert expand_cidr("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_cidr_expands_all_hosts() -> None:
    assert expand_cidr("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_remove_duplicates_keeps_distinct_cidrs_with_shared_first_host() -> None:
    entries = ["10.0.0.0/24", "10.0.0.0/16"]

    assert remove_duplicates(entries) == entries


def test_remove_duplicates_collapses_ip_and_slash_32() -> None:
    entries = ["10.0.0.1", "10.0.0.1/32"]

    assert remove_duplicates(entries) == ["10.0.0.1"]


def test_remove_duplicates_keeps_first_seen_formatting() -> None:
    entries = ["10.0.0.1", "10.0.0.1", "example.com", "example.com"]

    assert remove_duplicates(entries) == ["10.0.0.1", "example.com"]


def test_partition_targets_splits_public_and_private_ips() -> None:
    partition = partition_targets(["8.8.8.8", "10.0.0.1"])

    assert partition.public_ips == ["8.8.8.8"]
    assert partition.private_ips == {"10.0.0.1": []}
    assert partition.pending_hostnames == []


def test_partition_targets_records_cidr_as_private_ip_source() -> None:
    partition = partition_targets(["10.0.0.0/30"])

    assert partition.public_ips == []
    assert partition.private_ips == {
        "10.0.0.1": ["10.0.0.0/30"],
        "10.0.0.2": ["10.0.0.0/30"],
    }


def test_partition_targets_merges_sources_for_the_same_private_ip() -> None:
    partition = partition_targets(["10.0.0.1", "10.0.0.0/30"])

    assert partition.private_ips["10.0.0.1"] == ["10.0.0.0/30"]


def test_partition_targets_queues_hostnames_for_resolution() -> None:
    partition = partition_targets(["example.com"])

    assert partition.pending_hostnames == ["example.com"]
    assert partition.public_ips == []
    assert partition.private_ips == {}
