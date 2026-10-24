"""Exact-tool grants. Signatures are real. No appliance and no production token.

    .venv/bin/python -m pytest tests/test_tool_grants.py -q
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from vcf_mcp import client, config
from vcf_mcp.authz import ALLOWED_TOOLS, CAPABILITY, WRITE_TOOLS
from vcf_mcp.oauth_bearer import (
    VCF_READ_SCOPES,
    VCF_WRITE_SCOPES,
    authorize_token,
    tools_from_claims,
)
from vcf_mcp.server import vcf_reset_vm, vcf_start_vm, vcf_stop_vm, vcf_suspend_vm

ISSUER = "https://issuer.example.test/tenant"
RESOURCE = "https://vcf.example.test/mcp"
GATEWAY = "https://gateway.example.test/tenant/mcp/route-a"
READS = ["tools", *VCF_READ_SCOPES]
WRITES = list(VCF_WRITE_SCOPES)
POWER = (
    ("vcf_start_vm", vcf_start_vm),
    ("vcf_stop_vm", vcf_stop_vm),
    ("vcf_reset_vm", vcf_reset_vm),
    ("vcf_suspend_vm", vcf_suspend_vm),
)


@pytest.fixture
def oauth_env():
    env = {
        "VCF_MCP_OAUTH_ISSUER": ISSUER + "/",
        "VCF_MCP_RESOURCE_URL": RESOURCE,
        "VCF_MCP_OAUTH_AUDIENCES": GATEWAY,
        "VCF_MCP_GATEWAY_JOB_MAP": "",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        yield


def _pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": "test", "use": "sig", "alg": "RS256"})
    return private, {"keys": [jwk]}


def _sign(private, **claims) -> str:
    body = {"iss": ISSUER, "aud": RESOURCE, "exp": int(time.time()) + 120}
    body.update(claims)
    return jwt.encode(body, private, algorithm="RS256", headers={"kid": "test"})


def _http(allowed: set[str], writes: set[str]):
    return (
        CAPABILITY.set("read"),
        ALLOWED_TOOLS.set(frozenset(allowed)),
        WRITE_TOOLS.set(frozenset(writes)),
    )


def _reset(tokens) -> None:
    WRITE_TOOLS.reset(tokens[2])
    ALLOWED_TOOLS.reset(tokens[1])
    CAPABILITY.reset(tokens[0])


def test_exact_intent_does_not_cover_a_second_tool():
    claims = {"scope": "urn:iam:agent:intent:vcf_start_vm"}
    allowed, writes = tools_from_claims(claims, read_scopes=READS, write_scopes=WRITES)
    assert allowed == frozenset({"vcf_start_vm"})
    assert writes == frozenset({"vcf_start_vm"})


def test_tools_scope_cannot_mutate():
    allowed, writes = tools_from_claims({"scope": "tools"}, read_scopes=READS, write_scopes=WRITES)
    assert "vcf_list_vms" in allowed
    assert "vcf_call" in allowed
    assert writes == frozenset()
    assert "vcf_start_vm" not in allowed


def test_migration_map_is_explicit_and_fail_closed(oauth_env):
    generic = {"scope": "urn:iam:agent:intent:vcf-inspection"}
    assert tools_from_claims(generic, read_scopes=READS, write_scopes=WRITES) == (frozenset(), frozenset())
    mapped = json.dumps({"urn:iam:agent:intent:vcf-inspection": ["vcf_list_vms"]})
    with mock.patch.dict(os.environ, {"VCF_MCP_GATEWAY_JOB_MAP": mapped}):
        allowed, writes = tools_from_claims(generic, read_scopes=READS, write_scopes=WRITES)
    assert allowed == frozenset({"vcf_list_vms"})
    assert writes == frozenset()
    with mock.patch.dict(os.environ, {"VCF_MCP_GATEWAY_JOB_MAP": "not-json"}):
        assert tools_from_claims(generic, read_scopes=READS, write_scopes=WRITES)[0] == frozenset()


def test_signed_token_allows_one_read_and_rejects_bad_tokens(oauth_env):
    from vcf_mcp import oauth_bearer as ob

    private, jwks = _pair()
    other, _other_jwks = _pair()
    good = _sign(private, scope="urn:iam:agent:intent:vcf_list_vms")
    expired = _sign(private, scope="urn:iam:agent:intent:vcf_list_vms", exp=int(time.time()) - 30)
    forged = _sign(other, scope="urn:iam:agent:intent:vcf_list_vms")
    generic = _sign(private, scope="urn:iam:agent:intent:vcf-inspection")
    with mock.patch.object(ob, "_load_jwks", return_value=jwks):
        capability, allowed, writes = authorize_token(
            good, default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES
        )
        assert capability == "read"
        assert allowed == frozenset({"vcf_list_vms"})
        assert writes == frozenset()
        assert authorize_token(expired, default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES)[0] is None
        assert authorize_token(forged, default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES)[0] is None
        assert authorize_token(generic, default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES)[0] is None
        assert authorize_token("", default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES)[0] is None
        assert authorize_token("not-a-jwt", default_resource=RESOURCE, read_scopes=READS, write_scopes=WRITES)[0] is None


@pytest.mark.parametrize("name,func", POWER)
def test_read_credential_cannot_power_a_vm(name, func, monkeypatch):
    tokens = _http(set(VCF_READ_SCOPES), set())

    def boom(*_a, **_k):
        raise AssertionError("downstream")

    monkeypatch.setattr(config, "get_target", boom)
    monkeypatch.setattr(config, "require_host", boom)
    monkeypatch.setattr(client, "request", boom)
    monkeypatch.setattr("vcf_mcp.auth.headers_for", boom)
    try:
        result = asyncio.run(func("vm-1"))
    finally:
        _reset(tokens)
    assert result["tool"] == name
    assert result["authorization"] == "insufficient"
    assert result["enforced_by"] == "agentminder-grant"


def test_named_write_tool_does_not_authorize_its_neighbour(monkeypatch):
    tokens = _http({"vcf_start_vm"}, {"vcf_start_vm"})
    seen: list[str] = []

    def fake_request(_target, method, path, **_k):
        seen.append(f"{method} {path}")
        return 200, {"state": "started"}, {}

    monkeypatch.setattr(config, "get_target", lambda _name: config.Target(
        name="vcenter", product="vcenter", host="203.0.113.10", auth="vcenter_session", specs=(),
    ))
    monkeypatch.setattr(client, "request", fake_request)

    def boom(*_a, **_k):
        raise AssertionError("neighbour")

    try:
        started = asyncio.run(vcf_start_vm("vm-1"))
        monkeypatch.setattr(client, "request", boom)
        monkeypatch.setattr(config, "get_target", boom)
        stopped = asyncio.run(vcf_stop_vm("vm-1"))
    finally:
        _reset(tokens)
    assert started["ok"] is True
    assert seen == ["POST /api/vcenter/vm/vm-1/power?action=start"]
    assert stopped["authorization"] == "insufficient"
    assert stopped["enforced_by"] == "agentminder-grant"


def test_operation_guard_still_refuses_when_the_name_was_allowed(monkeypatch):
    """A grant entry is not a mutation. The operation guard remains."""
    tokens = _http({"vcf_start_vm"}, set())

    def boom(*_a, **_k):
        raise AssertionError("appliance")

    monkeypatch.setattr(config, "get_target", boom)
    monkeypatch.setattr(config, "require_host", boom)
    monkeypatch.setattr(client, "request", boom)
    monkeypatch.setattr("vcf_mcp.auth.headers_for", boom)
    try:
        result = asyncio.run(vcf_start_vm("vm-1"))
    finally:
        _reset(tokens)
    assert result["authorization"] == "denied"
    assert result["enforced_by"] == "vcf-mcp"
