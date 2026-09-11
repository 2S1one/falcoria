from falcoria_contracts import temporal_names


def test_names_are_distinct() -> None:
    names = [
        temporal_names.SCAN_WORKFLOW_NAME,
        temporal_names.SCAN_BATCH_WORKFLOW_NAME,
        temporal_names.PORT_SCANNER_TASK_QUEUE,
        temporal_names.QUERY_GET_PROGRESS,
        temporal_names.SEARCH_ATTR_PROJECT_ID,
        temporal_names.SEARCH_ATTR_SCAN_ID,
        temporal_names.SEARCH_ATTR_MODE,
        temporal_names.SEARCH_ATTR_IP,
    ]

    assert len(names) == len(set(names))
    assert all(isinstance(name, str) and name for name in names)
