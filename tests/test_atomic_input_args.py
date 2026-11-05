"""Atomic InputArgs key hygiene."""

from __future__ import annotations

import pytest

from corvex.atomic.runner import AtomicGateError, build_invoke_script


def test_input_args_accepts_identifier_keys() -> None:
    s = build_invoke_script(
        technique="T1003",
        test_number=1,
        get_prereqs=False,
        cleanup=False,
        input_args={"Path": r"C:\tmp"},
        phase="test",
    )
    assert "Path =" in s
    assert "Invoke-AtomicTest" in s


def test_input_args_rejects_non_identifier_keys() -> None:
    with pytest.raises(AtomicGateError):
        build_invoke_script(
            technique="T1003",
            test_number=1,
            get_prereqs=False,
            cleanup=False,
            input_args={"bad; key": "x"},
            phase="test",
        )
