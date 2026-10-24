"""Read credentials cannot mutate. No appliance is contacted.

    .venv/bin/python -m pytest tests/test_mutation_authz.py -q
"""
from __future__ import annotations

import asyncio

import pytest

from vcf_mcp import client, config, tools
from vcf_mcp.authz import CAPABILITY, Denied, authorize_mutation
from vcf_mcp.server import vcf_call

POWER = (
    ("start", tools.start_vm, "start"),
    ("stop", tools.stop_vm, "stop"),
    ("reset", tools.reset_vm, "reset"),
    ("suspend", tools.suspend_vm, "suspend"),
)


def _target() -> config.Target:
    return config.Target(
        name="vcenter",
        product="vcenter",
        host="203.0.113.10",
        auth="vcenter_session",
        specs=(),
    )


@pytest.fixture
def capability():
    token = None

    def _set(value: str) -> None:
        nonlocal token
        token = CAPABILITY.set(value)

    yield _set
    if token is not None:
        CAPABILITY.reset(token)


def test_decision_table():
    assert authorize_mutation("admin") == "permit"
    assert authorize_mutation("read") == "denied"
    assert authorize_mutation(None) == "missing"
    assert authorize_mutation("") == "missing"
    assert authorize_mutation("   ") == "missing"
    assert authorize_mutation("write") == "malformed"
    assert authorize_mutation("READ") == "malformed"
    assert authorize_mutation("admin ") == "permit"


@pytest.mark.parametrize("name,func,action", POWER)
def test_power_tools_deny_read_before_any_request(name, func, action, capability, monkeypatch):
    capability("read")

    def boom(*_a, **_k):
        raise AssertionError("downstream call")

    monkeypatch.setattr(client, "request", boom)
    result = func("vm-1")
    assert result["ok"] is False
    assert result["authorization"] == "denied"
    assert result["enforced_by"] == "vcf-mcp"
    assert name


@pytest.mark.parametrize("name,func,action", POWER)
def test_power_tools_permit_admin_against_a_mock(name, func, action, capability, monkeypatch):
    capability("admin")
    seen: list[str] = []

    def fake_request(_target, method, path, **_k):
        seen.append(f"{method} {path}")
        return 200, {"state": action}, {}

    monkeypatch.setattr(config, "get_target", lambda _name: _target())
    monkeypatch.setattr(client, "request", fake_request)
    result = func("vm-1")
    assert result["ok"] is True
    assert seen == [f"POST /api/vcenter/vm/vm-1/power?action={action}"]


def test_request_refuses_before_host_lookup(capability, monkeypatch):
    capability("read")

    def boom(*_a, **_k):
        raise AssertionError("host lookup")

    monkeypatch.setattr(config, "require_host", boom)
    monkeypatch.setattr(client, "_send", boom)
    with pytest.raises(Denied) as caught:
        client.request(_target(), "DELETE", "/v1/domains/domain-1")
    assert caught.value.reason == "denied"


@pytest.mark.parametrize("cap,reason", [("", "missing"), ("not-a-role", "malformed")])
def test_request_rejects_missing_and_malformed(cap, reason, capability, monkeypatch):
    capability(cap)
    monkeypatch.setattr(client, "_send", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("send")))
    with pytest.raises(Denied) as caught:
        client.request(_target(), "POST", "/v1/hosts")
    assert caught.value.reason == reason


def test_admin_post_reaches_the_mock_transport(capability, monkeypatch):
    capability("admin")
    monkeypatch.setattr("vcf_mcp.auth.headers_for", lambda *_a, **_k: {})
    monkeypatch.setattr(client, "_send", lambda *_a, **_k: (202, {"id": "task-1"}, {}))
    status, body, _headers = client.request(_target(), "POST", "/v1/hosts", body={"fqdn": "esxi.example"})
    assert status == 202
    assert body["id"] == "task-1"


def test_read_get_is_not_a_mutation(capability, monkeypatch):
    capability("read")
    monkeypatch.setattr("vcf_mcp.auth.headers_for", lambda *_a, **_k: {})
    monkeypatch.setattr(client, "_send", lambda *_a, **_k: (200, {"value": []}, {}))
    status, _body, _headers = client.request(_target(), "GET", "/api/vcenter/vm")
    assert status == 200


def test_read_shaped_post_is_explicit(capability, monkeypatch):
    capability("read")
    monkeypatch.setattr("vcf_mcp.auth.headers_for", lambda *_a, **_k: {})
    monkeypatch.setattr(client, "_send", lambda *_a, **_k: (200, {"alerts": []}, {}))
    status, _body, _headers = client.request(
        _target(), "POST", "/suite-api/api/alerts/query", mutation=False,
    )
    assert status == 200


def test_generic_handler_denies_before_tools_call(capability, monkeypatch):
    capability("read")

    def boom(*_a, **_k):
        raise AssertionError("tools.call")

    monkeypatch.setattr(tools, "call", boom)
    result = asyncio.run(vcf_call("vcenter", "POST", "/api/vcenter/vm/vm-1/power?action=stop"))
    assert result["authorization"] == "denied"
    assert result["enforced_by"] == "vcf-mcp"


def test_generic_handler_allows_admin_to_the_mock(capability, monkeypatch):
    capability("admin")
    monkeypatch.setattr(
        tools,
        "call",
        lambda **_k: {"ok": True, "enforced_by": "vcf-mcp", "mock": True},
    )
    result = asyncio.run(vcf_call("vcenter", "POST", "/v1/hosts"))
    assert result["ok"] is True


def test_task_scope_is_not_a_write_scope():
    from vcf_mcp.oauth_bearer import VCF_READ_SCOPES, VCF_WRITE_SCOPES

    assert "vcf_task" in VCF_READ_SCOPES
    assert "vcf_task" not in VCF_WRITE_SCOPES
    assert "vcf_start_vm" in VCF_WRITE_SCOPES
