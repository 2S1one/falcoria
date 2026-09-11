from falcoria_temporal.search_attributes import SA_IP, SA_MODE, SA_PROJECT_ID, SA_SCAN_ID


def test_keys_are_distinct_keywords() -> None:
    keys = [SA_PROJECT_ID, SA_SCAN_ID, SA_MODE, SA_IP]
    names = [key.name for key in keys]

    assert len(names) == len(set(names))
