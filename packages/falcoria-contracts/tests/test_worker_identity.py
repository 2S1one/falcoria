from falcoria_contracts.worker_identity import build_worker_identity, parse_worker_identity


def test_round_trips_a_well_formed_identity() -> None:
    identity = build_worker_identity(pid=123, hostname="worker-1", external_ip="10.0.0.5")

    parsed = parse_worker_identity(identity)

    assert parsed.pid == 123
    assert parsed.hostname == "worker-1"
    assert parsed.external_ip == "10.0.0.5"


def test_falls_back_to_the_whole_string_without_an_at_sign() -> None:
    parsed = parse_worker_identity("worker-1:10.0.0.5")

    assert parsed.pid is None
    assert parsed.hostname == "worker-1:10.0.0.5"
    assert parsed.external_ip is None


def test_falls_back_to_no_external_ip_without_a_colon() -> None:
    parsed = parse_worker_identity("123@worker-1")

    assert parsed.pid == 123
    assert parsed.hostname == "worker-1"
    assert parsed.external_ip is None


def test_non_numeric_pid_segment_is_none() -> None:
    parsed = parse_worker_identity("not-a-pid@worker-1:10.0.0.5")

    assert parsed.pid is None
    assert parsed.hostname == "worker-1"
    assert parsed.external_ip == "10.0.0.5"
