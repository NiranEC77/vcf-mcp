"""Per-tool AgentMinder grants on fixture claims. No production token.

    .venv/bin/python -m pytest tests/test_agentminder_gate.py -q
"""
from __future__ import annotations

from vcf_mcp.agentminder_gate import demonstrate, invoke, judge

NOW = 1_800_000_000.0


def _claims(tools: list[str], **overrides):
    from vcf_mcp.agentminder_gate import _claims

    base = _claims(tools, exp=NOW + 60)
    base.update(overrides)
    return base


def test_read_grant_permits_the_read_and_denies_the_write():
    ran: list[str] = []
    read = _claims(["vcf_list_vms"])
    allowed = invoke(read, "vcf_list_vms", lambda tool: ran.append(tool) or {"mock": True}, now=NOW)
    refused = invoke(read, "vcf_start_vm", lambda tool: ran.append(tool) or {"mock": True}, now=NOW)
    assert allowed["authorization"] == "permit"
    assert allowed["downstream_called"] is True
    assert allowed["enforced_by"] == "agentminder-grant"
    assert refused["authorization"] == "denied"
    assert refused["downstream_called"] is False
    assert ran == ["vcf_list_vms"]


def test_write_grant_permits_the_mock_write():
    ran: list[str] = []
    result = invoke(
        _claims(["vcf_start_vm"]),
        "vcf_start_vm",
        lambda tool: ran.append(tool) or {"mock": True, "powered": False},
        now=NOW,
    )
    assert result["ok"] is True
    assert result["result"]["powered"] is False
    assert ran == ["vcf_start_vm"]


def test_missing_expired_and_invalid_never_call_downstream():
    ran: list[str] = []

    def downstream(tool: str):
        ran.append(tool)
        return {"mock": True}

    missing = invoke(None, "vcf_list_vms", downstream, now=NOW)
    expired = invoke(_claims(["vcf_list_vms"], exp=NOW - 1), "vcf_list_vms", downstream, now=NOW)
    invalid = invoke(_claims(["vcf_list_vms"], iss="not-agentminder"), "vcf_list_vms", downstream, now=NOW)
    malformed = invoke(["not-claims"], "vcf_list_vms", downstream, now=NOW)
    assert missing["authorization"] == "missing"
    assert expired["authorization"] == "expired"
    assert invalid["authorization"] == "invalid"
    assert malformed["authorization"] == "malformed"
    assert ran == []
    assert judge(_claims(["vcf_list_vms"], aud="other"), "vcf_list_vms", now=NOW) == "invalid"


def test_demonstrate_records_only_the_two_permits():
    report = demonstrate(now=NOW)
    assert report["production_grants_changed"] is False
    assert report["downstream_calls"] == ["vcf_list_vms", "vcf_start_vm"]
    outcomes = [row["authorization"] for row in report["cases"]]
    assert outcomes == ["permit", "denied", "permit", "missing", "expired", "invalid"]
