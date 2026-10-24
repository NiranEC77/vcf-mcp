"""Capability check for a mutating VCF call.

Read-only credentials never authorize a mutation. The check is a pure
function: it does not open a socket. ``client.request`` calls it before
it resolves a host or mints an appliance token.
"""

from __future__ import annotations

from contextvars import ContextVar

# Stdio has no bearer, so the default stays admin. HTTP mode sets this
# from the presented token before the tool runs, and then lowers it to
# read until the invoked tool is bound.
CAPABILITY: ContextVar[str] = ContextVar("capability", default="admin")

# None means stdio: the operating system user launched the process.
# HTTP mode always sets both. An empty set means the token named no tool.
ALLOWED_TOOLS: ContextVar[frozenset[str] | None] = ContextVar("allowed_tools", default=None)
WRITE_TOOLS: ContextVar[frozenset[str] | None] = ContextVar("write_tools", default=None)

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


def bind_tool(name: str) -> tuple[dict | None, object | None]:
    """Match the grant to this tool, then set read or admin for this call.

    Returns ``(denial, reset_token)``. A denial means the tool function
    must not run. ``reset_token`` is passed to ``reset_tool`` afterwards.

    Stdio leaves both sets unset and is unchanged. HTTP always sets them.
    A tool that is granted only as a read does not become admin, so the
    operation guard still refuses a mutation.
    """
    allowed = ALLOWED_TOOLS.get()
    writes = WRITE_TOOLS.get()
    if allowed is None and writes is None:
        return None, None
    granted = allowed or frozenset()
    if name not in granted:
        return (
            {
                "ok": False,
                "denied": True,
                "authorization": "insufficient",
                "tool": name,
                "enforced_by": "agentminder-grant",
                "error": "authorization insufficient",
            },
            None,
        )
    capability = "admin" if writes is not None and name in writes else "read"
    return None, CAPABILITY.set(capability)


def reset_tool(token: object | None) -> None:
    if token is not None:
        CAPABILITY.reset(token)  # type: ignore[arg-type]
