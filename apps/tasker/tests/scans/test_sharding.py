from falcoria_tasker.scans.sharding import shard_ports


def test_shard_count_le_1_returns_single_shard() -> None:
    ports = ["22", "80", "1000-2000"]

    assert shard_ports(ports, 1) == [ports]
    assert shard_ports(ports, 0) == [ports]


def test_shards_single_ports_without_splitting() -> None:
    shards = shard_ports(["22", "80", "443", "8080"], 2)

    assert len(shards) == 2
    assert sum(len(shard) for shard in shards) == 4
    flattened = [port for shard in shards for port in shard]
    assert sorted(flattened) == ["22", "443", "80", "8080"]


def test_splits_a_range_at_shard_boundary() -> None:
    shards = shard_ports(["1-10"], 2)

    assert shards == [["1-5"], ["6-10"]]


def test_balances_total_port_count_across_shards() -> None:
    shards = shard_ports(["1-100"], 4)

    counts = []
    for shard in shards:
        total = 0
        for spec in shard:
            if "-" in spec:
                start, end = spec.split("-")
                total += int(end) - int(start) + 1
            else:
                total += 1
        counts.append(total)

    assert counts == [25, 25, 25, 25]


def test_does_not_split_a_single_port() -> None:
    shards = shard_ports(["22", "1-9"], 2)

    assert all(port_spec != "" for shard in shards for port_spec in shard)
    flattened = [spec for shard in shards for spec in shard]
    assert "22" in flattened
