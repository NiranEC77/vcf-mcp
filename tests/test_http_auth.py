"""HTTP-mode bearer rules. No network, no live tokens.

Pinned because it shipped wrong once: a backend that re-checks tool names
refused every token whose only grant was a gateway job scope, and the
gateway reported that 401 as "backend unavailable".

    .venv/bin/python -m pytest tests/test_http_auth.py -q
"""
from __future__ import annotations

import os
from unittest import mock

import pytest

from vcf_mcp import oauth_bearer as ob
from vcf_mcp import server

RESOURCE = "https://vcf.example.test/mcp"
GATEWAY = "https://gateway.example.test/tenant/mcp/route-a"
JOB = "urn:iam:agent:intent:vcf-inspection"


@pytest.fixture
def oauth_env():
    env = {
        "VCF_MCP_OAUTH_ISSUER": "https://issuer.example.test/tenant/",
        "VCF_MCP_RESOURCE_URL": RESOURCE,
        "VCF_MCP_OAUTH_AUDIENCES": GATEWAY + ",",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        yield


# --- pure claim rules ------------------------------------------------------

def test_issuer_strips_trailing_slash(oauth_env):
    assert ob.issuer() == "https://issuer.example.test/tenant"
    assert ob.enabled()


def test_disabled_without_issuer():
    with mock.patch.dict(os.environ, {"VCF_MCP_OAUTH_ISSUER": ""}, clear=False):
        assert not ob.enabled()
        assert ob.verify_jwt("a.b.c") is None


def test_audiences_include_own_url_and_gateway(oauth_env):
    auds = ob.audiences()
    assert RESOURCE in auds
    assert GATEWAY in auds
    assert ob.audience_ok({"aud": [GATEWAY, "https://issuer.example.test/tenant/"]}, auds)
    assert ob.audience_ok({"aud": RESOURCE + "/"}, auds)
    assert not ob.audience_ok({"aud": "https://other.example.test/mcp"}, auds)


def test_tool_name_scopes_decide_capability():
    reads = ["tools", *ob.VCF_READ_SCOPES]
    writes = list(ob.VCF_WRITE_SCOPES)
    assert ob.capability_for({"scope": "vcf_call vcf_targets"}, read_scopes=reads, write_scopes=writes) == "admin"
    assert ob.capability_for({"scope": "vcf_targets vcf_audit"}, read_scopes=reads, write_scopes=writes) == "read"
    assert ob.capability_for({"scope": "tools"}, read_scopes=reads, write_scopes=writes) == "read"
    assert ob.capability_for({"scope": "openid profile"}, read_scopes=reads, write_scopes=writes) is None


def test_gateway_job_scope_is_enough():
    """The gateway mapped tool -> job -> policy. This server does not redo it."""
    claims = {"scope": f"{JOB} vcf-inspection urn:iam:m.meclient"}
    assert ob.intent_scopes(claims) == [JOB]
    assert ob.intent_grant(claims)
    assert not ob.grant_ok(claims, ob.expand_read_scopes(["tools"]))
    assert (
        ob.capability_for(claims, read_scopes=["tools", *ob.VCF_READ_SCOPES], write_scopes=list(ob.VCF_WRITE_SCOPES))
        == "admin"
    )


def test_intent_prefix_is_configurable():
    with mock.patch.dict(os.environ, {"VCF_MCP_OAUTH_INTENT_PREFIX": "urn:acme:job:"}, clear=False):
        assert ob.intent_grant({"scope": "urn:acme:job:read-estate"})
        assert not ob.intent_grant({"scope": JOB})


def test_scp_claim_is_read_too():
    assert ob.intent_grant({"scp": [JOB]})
    assert ob.scopes_of({"scp": ["a", "b"], "scope": "c"}) == {"a", "b", "c"}
    assert ob.scopes_of(None) == set()


# --- classify with verification mocked --------------------------------------

def test_classify_accepts_job_token_for_this_resource(oauth_env):
    claims = {"scope": JOB, "aud": [GATEWAY]}
    with mock.patch.object(ob, "verify_jwt", return_value=claims):
        assert (
            ob.classify("h.p.s", default_resource=RESOURCE, read_scopes=["tools"], write_scopes=["vcf_call"])
            == "admin"
        )


def test_classify_rejects_wrong_audience_and_empty_scope(oauth_env):
    with mock.patch.object(ob, "verify_jwt", return_value={"scope": JOB, "aud": ["https://other.example.test"]}):
        assert ob.classify("h.p.s", default_resource=RESOURCE, read_scopes=["tools"]) is None
    with mock.patch.object(ob, "verify_jwt", return_value={"scope": "urn:iam:m.meclient", "aud": [RESOURCE]}):
        assert ob.classify("h.p.s", default_resource=RESOURCE, read_scopes=["tools"]) is None
    assert ob.classify("not-a-jwt", default_resource=RESOURCE, read_scopes=["tools"]) is None


# --- server gate ----------------------------------------------------------------

def test_static_tokens_win_and_are_constant_time(oauth_env):
    env = {"VCF_ADMIN_TOKEN": "a" * 20, "VCF_READ_TOKEN": "r" * 20}
    with mock.patch.dict(os.environ, env, clear=False):
        assert server._classify_token("a" * 20) == "admin"
        assert server._classify_token("r" * 20) == "read"
        assert server._classify_token("") is None
        assert server._classify_token(None) is None


def test_gate_falls_through_to_oauth_only_when_configured():
    env = {"VCF_ADMIN_TOKEN": "a" * 20, "VCF_READ_TOKEN": "r" * 20, "VCF_MCP_OAUTH_ISSUER": ""}
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch.object(ob, "classify") as classify:
            assert server._classify_token("h.p.s") is None
            classify.assert_not_called()
    env["VCF_MCP_OAUTH_ISSUER"] = "https://issuer.example.test/t"
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch.object(ob, "classify", return_value="admin") as classify:
            assert server._classify_token("h.p.s") == "admin"
            classify.assert_called_once()


def test_http_refuses_to_start_without_any_bearer():
    env = {"VCF_ADMIN_TOKEN": "", "VCF_READ_TOKEN": "", "VCF_MCP_OAUTH_ISSUER": ""}
    with mock.patch.dict(os.environ, env, clear=False):
        problems = server._http_token_problems()
    assert problems and "Refusing to start" in problems[0]


def test_http_starts_with_oauth_only():
    env = {"VCF_ADMIN_TOKEN": "", "VCF_READ_TOKEN": "", "VCF_MCP_OAUTH_ISSUER": "https://issuer.example.test/t"}
    with mock.patch.dict(os.environ, env, clear=False):
        assert server._http_token_problems() == []


def test_allowed_hosts_follow_resource_url():
    env = {"VCF_ALLOWED_HOSTS": "", "VCF_MCP_RESOURCE_URL": RESOURCE, "PORT": "8098"}
    with mock.patch.dict(os.environ, env, clear=False):
        hosts = server._allowed_hosts()
    assert hosts[0] == "vcf.example.test"
    assert "127.0.0.1:8098" in hosts
    with mock.patch.dict(os.environ, {"VCF_ALLOWED_HOSTS": "a.example, b.example"}, clear=False):
        assert server._allowed_hosts() == ["a.example", "b.example"]


def test_metadata_names_issuer_only_when_enabled(oauth_env):
    doc = ob.protected_resource(default_resource=RESOURCE, scopes=["tools"], name="vcf-mcp")
    assert doc["authorization_servers"] == ["https://issuer.example.test/tenant"]
    assert doc["resource"] == RESOURCE
    with mock.patch.dict(os.environ, {"VCF_MCP_OAUTH_ISSUER": ""}, clear=False):
        assert "authorization_servers" not in ob.protected_resource(default_resource=RESOURCE, scopes=["tools"], name="x")
    assert ob.is_opr_path("/.well-known/oauth-protected-resource/mcp?x=1")
    assert not ob.is_opr_path("/mcp")
