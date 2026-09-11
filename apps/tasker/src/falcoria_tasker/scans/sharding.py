"""Pure port-range sharding: splits port specs into balanced count shards."""

import math


def _count_ports(spec: str) -> int:
    if "-" in spec:
        start, end = spec.split("-")
        return int(end) - int(start) + 1
    return 1


def shard_ports(port_specs: list[str], shard_count: int) -> list[list[str]]:
    """Splits port_specs into shard_count shards balanced by total port count.

    A range spec (e.g. "1000-2000") may be split across two shards at the
    boundary; single ports are never split. shard_count <= 1 returns the
    input as one shard, unchanged.
    """
    if shard_count <= 1:
        return [port_specs]

    total = sum(_count_ports(spec) for spec in port_specs)
    target = math.ceil(total / shard_count)
    shards: list[list[str]] = []
    current: list[str] = []
    current_count = 0

    for spec in port_specs:
        spec_count = _count_ports(spec)
        if spec_count <= target - current_count:
            current.append(spec)
            current_count += spec_count
        else:
            start = int(spec.split("-")[0]) if "-" in spec else int(spec)
            while spec_count > 0:
                take = min(spec_count, target - current_count)
                end = start + take - 1
                current.append(str(start) if start == end else f"{start}-{end}")
                current_count += take
                spec_count -= take
                start = end + 1
                if current_count >= target and spec_count > 0:
                    shards.append(current)
                    current, current_count = [], 0
        if current_count >= target:
            shards.append(current)
            current, current_count = [], 0

    if current:
        shards.append(current)
    return shards
