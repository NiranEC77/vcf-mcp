"""Fixture-only per-tool grant check.

Production HTTP does not call this module. A fixture claim is not a
credential. The live path is ``oauth_bearer.authorize_token``, which
accepts a token only after signature, issuer, audience, and expiry
checks.



AgentMinder authorises a call by intent scope
``urn:iam:agent:intent:<tool>``. This module applies that rule to fixture
claims and refuses before the tool function runs.

It does not call IDSP, does not read a production token, and does not
change the HTTP gate. The HTTP gate still treats any intent as admin,
because a gateway in front of the live server has already stripped the
tools the job does not cover. This gate is the proof that a per-tool
grant can refuse on its own.
"""

from __future__ import annotations

import time
from typing import Any, Callable

INTENT_PREFIX = "urn:iam:agent:intent:"
ISSUER = "disposable-agentminder"
AUDIENCE = "disposable-agentminder"

READ_TOOLS = frozenset(
    {
        "vcf_targets",
        "vcf_search_api",
        "vcf_describe_api",
        "vcf_validate",
        "vcf_inventory",
        "vcf_audit",
        "vcf_task",
        "vcf_list_vms",
        "vcf_get_vm",
        "vcf_vm_power_state",
        "vcf_list_networks",
        "vcf_list_segments",
        "vcf_list_gateways",
        "vcf_list_datastores",
        "vcf_get_datastore",
        "vcf_datastore_policy",
        "vcf_list_alerts",
        "vcf_ops_snapshot",
        "vcf_vm_disk_latency",
    }
)
WRITE_TOOLS = frozenset(
    {
        "vcf_call",
        "vcf_start_vm",
        "vcf_stop_vm",
        "vcf_reset_vm",
        "vcf_suspend_vm",
    }
)


def _scopes(claims: dict[str, Any]) -> set[str]:
    raw = claims.get("scope")
    if raw is None:
        raw = claims.get("scp")
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {part for part in raw.split() if part}
    if isinstance(raw, (list, tuple)):
        return {str(part) for part in raw if str(part)}
    return set()


def judge(claims: Any, tool: str, *, now: float | None = None) -> str:
    """Return permit, denied, missing, expired, invalid, or malformed.

    No tool function runs here.
    """
    if claims is None:
        return "missing"
    if not isinstance(claims, dict) or not tool:
        return "malformed"
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return "malformed"
    if float(exp) <= (time.time() if now is None else now):
        return "expired"
    if claims.get("iss") != ISSUER:
        return "invalid"
    aud = claims.get("aud")
    audiences = {aud} if isinstance(aud, str) else set(aud or [])
    if AUDIENCE not in audiences:
        return "invalid"
    if tool not in READ_TOOLS and tool not in WRITE_TOOLS:
        return "invalid"
    intent = INTENT_PREFIX + tool
    if intent not in _scopes(claims):
        return "denied"
    return "permit"


def invoke(
    claims: Any,
    tool: str,
    downstream: Callable[[str], Any],
    *,
    now: float | None = None,
) -> dict[str, Any]:
    """Decide, then call downstream only on permit."""
    outcome = judge(claims, tool, now=now)
    if outcome != "permit":
        return {
            "ok": False,
            "tool": tool,
            "authorization": outcome,
            "enforced_by": "agentminder-grant",
            "downstream_called": False,
        }
    result = downstream(tool)
    return {
        "ok": True,
        "tool": tool,
        "authorization": "permit",
        "enforced_by": "agentminder-grant",
        "downstream_called": True,
        "result": result,
    }


def _claims(tools: list[str], *, exp: float, iss: str = ISSUER, aud: str = AUDIENCE) -> dict[str, Any]:
    scopes = [INTENT_PREFIX + name for name in tools]
    return {"iss": iss, "aud": aud, "exp": exp, "scope": " ".join(scopes)}


def demonstrate(*, now: float = 1_800_000_000.0) -> dict[str, Any]:
    """Four cases. The downstream list is the evidence of what ran."""
    ran: list[str] = []

    def downstream(tool: str) -> dict[str, Any]:
        ran.append(tool)
        return {"mock": True, "tool": tool}

    future = now + 600
    past = now - 60
    read = _claims(["vcf_list_vms"], exp=future)
    write = _claims(["vcf_start_vm"], exp=future)
    cases = [
        invoke(read, "vcf_list_vms", downstream, now=now),
        invoke(read, "vcf_start_vm", downstream, now=now),
        invoke(write, "vcf_start_vm", downstream, now=now),
        invoke(None, "vcf_list_vms", downstream, now=now),
        invoke(_claims(["vcf_list_vms"], exp=past), "vcf_list_vms", downstream, now=now),
        invoke(_claims(["vcf_list_vms"], exp=future, iss="elsewhere"), "vcf_list_vms", downstream, now=now),
    ]
    return {
        "enforced_by": "agentminder-grant",
        "production_grants_changed": False,
        "downstream_calls": ran,
        "cases": cases,
    }
