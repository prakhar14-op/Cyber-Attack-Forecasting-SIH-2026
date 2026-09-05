"""Network kill-switch used by the offline tests and the smoke runner.

Passing tests under `network_disabled()` is what "offline" means for this project
(BUILD_PLAN M0.6): any attempt to construct a socket, resolve a name or open a
connection raises NetworkAttempt and fails the run.
"""

from __future__ import annotations

import socket
from contextlib import contextmanager


class NetworkAttempt(AssertionError):
    """A network call was attempted while the run is supposed to be offline."""


_BLOCKED_ATTRS = (
    "socket",
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


@contextmanager
def network_disabled():
    """Monkeypatch the socket module so every network primitive raises."""
    saved = {name: getattr(socket, name) for name in _BLOCKED_ATTRS}

    def _deny(name):
        def blocked(*args, **kwargs):
            raise NetworkAttempt(
                f"socket.{name} called while the network is disabled — "
                "offline is a hard constraint (CLAUDE.md #1)"
            )

        return blocked

    for name in _BLOCKED_ATTRS:
        setattr(socket, name, _deny(name))
    try:
        yield
    finally:
        for name, original in saved.items():
            setattr(socket, name, original)
