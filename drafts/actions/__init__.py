"""DRAFT ONLY — not installed in the corvex wheel.

Destructive Action verb stubs for Stage D design review.
CI and packaging must keep these out of the installable package.
"""

# Intentionally not imported by corvex.*


def isolate_host(host_id: str) -> None:
    raise RuntimeError("draft only — not executable in package")


def kill_process(host_id: str, pid: int) -> None:
    raise RuntimeError("draft only — not executable in package")


def contain_host(host_id: str) -> None:
    raise RuntimeError("draft only — not executable in package")
