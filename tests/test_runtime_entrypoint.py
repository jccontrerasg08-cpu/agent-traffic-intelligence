"""Tests for the explicit managed-runtime service entrypoint."""

from __future__ import annotations

import runpy
from unittest.mock import patch

import pytest


def test_runtime_module_delegates_to_server_main() -> None:
    """The module runner must preserve the server's exit status."""

    with (
        patch("agent_traffic_intelligence.runtime.server.main", return_value=0) as main,
        pytest.raises(SystemExit) as raised,
    ):
        runpy.run_module("agent_traffic_intelligence.runtime", run_name="__main__")

    assert raised.value.code == 0
    main.assert_called_once_with()
