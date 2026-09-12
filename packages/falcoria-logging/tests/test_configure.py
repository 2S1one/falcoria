import json
import logging

import pytest
from falcoria_logging import configure_logging


@pytest.fixture(autouse=True)
def _restore_root_logger():
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    yield
    root.handlers = original_handlers
    root.setLevel(original_level)


def test_rejects_unknown_level() -> None:
    with pytest.raises(ValueError, match="nonsense"):
        configure_logging(level="nonsense", json_output=False)


def test_sets_root_level() -> None:
    configure_logging(level="warning", json_output=False)

    assert logging.getLogger().level == logging.WARNING


def test_second_call_replaces_handlers_instead_of_stacking() -> None:
    configure_logging(level="info", json_output=False)
    configure_logging(level="info", json_output=False)

    assert len(logging.getLogger().handlers) == 1


def test_json_output_is_valid_json_with_expected_fields(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="info", json_output=True)
    logging.getLogger("falcoria_test").info("hello %s", "world")

    payload = json.loads(capsys.readouterr().out)

    assert payload["level"] == "INFO"
    assert payload["logger"] == "falcoria_test"
    assert payload["message"] == "hello world"


def test_text_output_is_plain(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="info", json_output=False)
    logging.getLogger("falcoria_test").info("hello world")

    out = capsys.readouterr().out

    assert "hello world" in out
    assert not out.startswith("{")


def test_quiets_third_party_loggers() -> None:
    configure_logging(level="debug", json_output=False)

    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING
