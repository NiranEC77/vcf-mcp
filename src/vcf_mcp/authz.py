"""Capability check for a mutating VCF call.

Read-only credentials never authorize a mutation. The check is a pure
function: it does not open a socket. ``client.request`` calls it before
it resolves a host or mints an appliance token.
"""

from __future__ import annotations

from contextvars import ContextVar

# Stdio has no bearer, so the default stays admin. HTTP mode sets this
# from the presented token before the tool runs.
CAPABILITY: ContextVar[str] = ContextVar("capability", default="admin")

READ_CAPABILITY = "read"
ADMIN_CAPABILITY = "admin"


class Denied(PermissionError):
    """The presented capability may not perform this mutation."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def authorize_mutation(capability: str | None) -> str:
    """Return permit, denied, missing, or malformed. No I/O."""
    if capability is None:
        return "missing"
    if not isinstance(capability, str):
        return "malformed"
    cap = capability.strip()
    if cap == "":
        return "missing"
    if cap == ADMIN_CAPABILITY:
        return "permit"
    if cap == READ_CAPABILITY:
        return "denied"
    return "malformed"


def require_mutation(capability: str | None = None) -> None:
    """Raise Denied unless the capability is exactly admin."""
    if capability is None:
        capability = CAPABILITY.get()
    outcome = authorize_mutation(capability)
    if outcome != "permit":
        raise Denied(outcome)
