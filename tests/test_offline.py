"""Tests that need no appliance -- run these anywhere.

They cover the parts that were actually wrong during the build: camelCase
tokenisation, plural stemming, $ref resolution, response truncation, secret
redaction, and task-id extraction. Each one is a bug that shipped and got
caught, so each one stays pinned.

    .venv/bin/python -m pytest tests/ -q
"""
from __future__ import annotations

import json

import pytest

from vcf_mcp import client, specs, tools


# --- tokenisation and ranking -------------------------------------------

def test_tokenize_splits_camel_case():
    assert specs._tokenize("checkAddHostEvc") == ["check", "add", "host", "evc"]
    assert "host" in specs._tokenize("commissionHosts")


def test_tokenize_stems_plurals():
    assert specs._tokenize("getDomains") == ["get", "domain"]
    assert specs._tokenize("clusters") == specs._tokenize("cluster")


def test_stem_handles_awkward_endings():
    assert specs._stem("policies") == "policy"
    assert specs._stem("addresses") == "address"
    assert specs._stem("status") == "status"  # not a plural
    assert specs._stem("dns") == "dns"  # too short to strip


@pytest.mark.parametrize(
    "query,target,method,path",
    [
        ("commission hosts", "sddc", "POST", "/v1/hosts"),
        ("list workload domains", "sddc", "GET", "/v1/domains"),
        ("rotate passwords", "sddc", "PATCH", "/v1/credentials"),
        ("list network pools", "sddc", "GET", "/v1/network-pools"),
        ("get alerts", "ops", "GET", "/suite-api/api/alerts"),
        ("list segments", "nsx", "GET", "/policy/api/v1/infra/segments"),
    ],
)
def test_search_finds_the_obvious_operation(query, target, method, path):
    results = specs.search(query, target=target, limit=5)["results"]
    assert any(r["method"] == method and r["path"] == path for r in results), [
        (r["method"], r["path"]) for r in results
    ]


def test_search_hides_deprecated_by_default():
    # updateEdgeCluster is deprecated in VCF 9.1.
    visible = specs.search("expand edge cluster", target="sddc", limit=30)["results"]
    assert not any(r["operationId"] == "updateEdgeCluster" for r in visible)
    including = specs.search(
        "expand edge cluster", target="sddc", limit=30, include_deprecated=True
    )["results"]
    assert any(r["operationId"] == "updateEdgeCluster" for r in including)


# --- spec plumbing -------------------------------------------------------

def test_base_path_for_both_dialects():
    # Swagger 2.0 states basePath outright; OpenAPI 3 hides it in servers[0].
    assert specs.base_path({"swagger": "2.0", "basePath": "/policy/api/v1"}) == "/policy/api/v1"
    assert specs.base_path({"openapi": "3.0.3", "servers": [{"url": "https://{host}/api"}]}) == "/api"
    assert specs.base_path({"openapi": "3.0.1", "servers": [{"url": "/suite-api"}]}) == "/suite-api"
    assert specs.base_path({"openapi": "3.0.1", "servers": [{"url": "http://localhost:80"}]}) == ""


def test_index_paths_include_base_path():
    entry = specs.find(target="ops", method="GET", path="/suite-api/api/alerts")
    assert entry["spec_path"] == "/api/alerts"


def test_describe_resolves_refs_not_bare_objects():
    """The cycle guard once pre-marked the ref it was resolving, so every
    schema collapsed to {"type": "object"}."""
    entry = specs.find(target="sddc", operation_id="commissionHosts")
    described = specs.describe(entry, depth=3)
    schema = described["request_body"]["schema"]
    assert schema["type"] == "array"
    properties = schema["items"]["properties"]
    assert "fqdn" in properties and "networkPoolId" in properties
    assert properties["fqdn"]["required"] is True


def test_describe_handles_swagger_two_body_parameter():
    entry = specs.find(target="nsx", method="PATCH", path="/policy/api/v1/infra/segments/{segment-id}")
    described = specs.describe(entry, depth=2, max_properties=5)
    assert described["request_body"] is not None
    assert described["request_body"]["schema"]["type"] == "object"


def test_find_reports_near_misses():
    with pytest.raises(LookupError) as excinfo:
        specs.find(target="sddc", operation_id="commissionHost")
    assert "Did you mean" in str(excinfo.value)


# --- response handling ---------------------------------------------------

def test_count_items_bare_list():
    """vCenter GET /api/vcenter/vm returns a JSON array. Three fields per
    VM must not become the count."""
    vms = [{"vm": f"vm-{i}", "name": f"n{i}", "power_state": "POWERED_ON"} for i in range(73)]
    assert tools.count_items(vms) == 73


def test_count_items_wrapped_collections():
    assert tools.count_items({"elements": [1, 2, 3]}) == 3
    assert tools.count_items({"value": [{"id": 1}]}) == 1
    assert tools.count_items({"resourceList": [{}, {}]}) == 2
    assert tools.count_items({"pagination": {"total_results": 40}, "results": [1]}) == 40
    assert tools.count_items({"datastores": [{}, {}]}) == 2
    assert tools.count_items({"pageInfo": {"totalCount": 9}, "resourceList": [1]}) == 9
    assert tools.count_items({"site": {"datastores": [{}, {}, {}]}}) == 3


def test_count_items_not_a_collection():
    assert tools.count_items({"id": "vm-1", "name": "one"}) is None
    assert tools.count_items("nope") is None
    assert tools.count_items(None) is None
    assert tools.count_items([]) == 0


def test_count_survives_truncation():
    """count is taken from the full payload. _fit may drop items."""
    payload = [{"a": "b" * 80} for _ in range(40)]
    assert tools.count_items(payload) == 40
    fitted, truncated = tools._fit(payload, 1500)
    assert truncated
    shown = fitted["items"] if isinstance(fitted, dict) else fitted
    assert len(shown) < 40


def test_fit_shrinks_the_longest_list_whatever_it_is_called():
    payload = {
        "pageInfo": {"totalCount": 80},
        "resourceList": [
            {"name": f"ds-{i}", "id": f"id-{i}", "type": "VSAN", "note": "z" * 80}
            for i in range(80)
        ],
    }
    fitted, truncated = tools._fit(payload, 2000)
    assert truncated
    assert len(fitted["resourceList"]) < 80
    assert "_truncated" in fitted
    assert len(json.dumps(fitted)) <= 2000


def test_fit_does_not_clip_a_list_item_to_an_opaque_string():
    """A fat vSAN object must stay a small dict. A 20k clipped string hid count."""
    payload = [
        {"name": "vsan-ds", "type": "VSAN", "blob": "x" * 50_000, "nested": {"cfg": "y" * 10_000}}
        for _ in range(3)
    ]
    fitted, truncated = tools._fit(payload, 4000)
    assert truncated
    items = fitted["items"] if isinstance(fitted, dict) else fitted
    assert fitted["count"] == 3
    assert items
    assert all(isinstance(i, dict) for i in items)
    assert all(not isinstance(i, str) for i in items)
    assert items[0].get("name") == "vsan-ds"
    assert "blob" not in items[0]
    text = json.dumps(fitted)
    assert "...<clipped>" not in text
    assert len(text) <= 4000


def test_call_leads_with_count_and_slims_items(monkeypatch):
    def fake_request(*_a, **_k):
        return (
            200,
            [
                {
                    "datastore": "datastore-15",
                    "name": "mgmt-cluster-ds-vsan01",
                    "type": "VSAN",
                    "free_space": 1,
                    "capacity": 2,
                    "blob": "x" * 50_000,
                }
            ],
            {},
        )

    monkeypatch.setattr(tools.client, "request", fake_request)
    out = tools.call("vcenter", "GET", "/api/vcenter/datastore")
    assert list(out)[0] == "count"
    assert out["count"] == 1
    assert out["summary"] == "1 items"
    assert out["items"][0]["name"] == "mgmt-cluster-ds-vsan01"
    assert "blob" not in out["items"][0]
    assert "...<clipped>" not in json.dumps(out)


def test_slim_item_keeps_datastore_identity():
    fat = {
        "datastore": "datastore-15",
        "name": "mgmt-cluster-ds-vsan01",
        "type": "VSAN",
        "free_space": 1,
        "capacity": 2,
        "vsan_config": {"disk": "z" * 8000},
    }
    slim = tools.slim_item(fat)
    assert slim["name"] == "mgmt-cluster-ds-vsan01"
    assert slim["type"] == "VSAN"
    assert "vsan_config" not in slim


def test_fit_leaves_small_payloads_alone():
    payload = {"elements": [1, 2, 3]}
    fitted, truncated = tools._fit(payload, 20_000)
    assert fitted == payload and not truncated


def test_fit_never_returns_broken_json_for_a_bare_list():
    fitted, truncated = tools._fit([{"a": "b" * 500} for _ in range(20)], 1500)
    assert truncated
    json.dumps(fitted)  # must round-trip


def test_redact_hides_secrets_at_any_depth():
    payload = {"spec": {"password": "hunter2", "nested": [{"sshThumbprint": "ok", "apiToken": "x"}]}}
    safe = client.redact(payload)
    assert safe["spec"]["password"] == "<redacted>"
    assert safe["spec"]["nested"][0]["apiToken"] == "<redacted>"
    assert safe["spec"]["nested"][0]["sshThumbprint"] == "ok"


# --- task detection ------------------------------------------------------

def test_task_id_ignores_ordinary_object_ids():
    """Every VCF object has an `id`; only a real task should be polled."""
    host = {"id": "000e5167-6564-425f-b5ae-abb6a4e32b9b", "fqdn": "esxi-11"}
    assert tools._task_id(200, host, {}) is None


def test_task_id_from_202_and_from_location_header():
    assert tools._task_id(202, {"id": "abc-123"}, {}) == "abc-123"
    assert tools._task_id(200, None, {"location": "/v1/tasks/def-456"}) == "def-456"


def test_task_id_recognises_a_task_shaped_body():
    body = {"id": "t-1", "status": "In Progress", "subTasks": []}
    assert tools._task_id(200, body, {}) == "t-1"


def test_terminal_states_are_case_insensitive():
    """SDDC Manager returns "Successful"; the docs say "SUCCESSFUL"."""
    assert "Successful".upper() in tools._TERMINAL
    assert "Successful".upper() in tools._SUCCEEDED
    assert "FAILED" in tools._FAILED


# --- round 2: field feedback from the first real user session ------------

def test_search_surfaces_high_scoring_hidden_deprecated():
    """A caller chasing a legacy path must learn it is legacy, not conclude
    the index is missing it."""
    found = specs.search("expand edge cluster", target="sddc", limit=5)
    hidden = found["hidden_deprecated"]
    assert any(h["operationId"] == "updateEdgeCluster" for h in hidden)
    assert all(h["deprecated"] is True for h in hidden)


def test_search_flags_deprecated_inline_when_included():
    found = specs.search(
        "enable supervisor on cluster", target="vcenter", limit=10, include_deprecated=True
    )
    legacy = [r for r in found["results"] if "namespace-management/clusters" in r["path"]]
    assert legacy and all(r.get("deprecated") for r in legacy)


def test_prose_enum_extraction():
    """vCenter's vAPI specs write enums as prose, not an enum key."""
    text = (
        "The provider.\n\nPossible values:\n"
        "  - `NSXT_CONTAINER_PLUGIN`: NSX Container Plugin.\n"
        "  - `VSPHERE_NETWORK`: vSphere Networking.\n"
        "  - `NSX_VPC`: NSX VPC.\n"
    )
    assert specs._prose_enum(text) == ["NSXT_CONTAINER_PLUGIN", "VSPHERE_NETWORK", "NSX_VPC"]
    # Ordinary backticks outside a "Possible values" section never count.
    assert specs._prose_enum("Use `pageSize` to limit results.") is None


def test_prose_enum_lands_in_described_schema():
    entry = specs.find(target="vcenter", operation_id="Vcenter.NamespaceManagement.Clusters_enable")
    described = specs.describe(entry, depth=3, max_properties=50)
    provider = described["request_body"]["schema"]["properties"]["network_provider"]
    assert "NSX_VPC" in provider["enum"]


def test_validate_twin_requires_exact_match():
    """Template matching would bind '.../supervisors/validations' to
    '.../supervisors/{supervisor}' and POST at a phantom resource."""
    result = tools.validate("vcenter", "/api/vcenter/namespace-management/supervisors")
    assert result["validated"] is False
    assert "no validation endpoint" in result["error"]
    assert result["alternatives"]  # check-style operations offered instead


# --- round 3: Avi Load Balancer target -----------------------------------

def test_avi_target_exists_with_object_specs():
    from vcf_mcp import config
    avi = config.get_target("avi")
    assert avi.auth == "avi_session"
    assert avi.credential_via == ("sddc", "NSX_ALB")
    assert len(avi.specs) == 170  # one spec per Avi object type


def test_avi_credentials_defer_to_store_instead_of_raising():
    """No .env key exists for Avi -- the empty list is the signal to fetch
    from SDDC Manager's credential store at auth time, not an error."""
    from vcf_mcp import config
    assert config.credentials(config.get_target("avi")) == []


def test_avi_paths_are_deduplicated():
    """Each Avi object spec re-declares related objects' paths; the index
    must carry each (method, path) exactly once."""
    seen = set()
    for entry in specs.index():
        if "avi" in entry["targets"]:
            key = (entry["method"], entry["path"])
            assert key not in seen, f"duplicate {key} from {entry['spec']}"
            seen.add(key)


def test_avi_dedupe_prefers_the_authoritative_spec():
    entry = specs.find(target="avi", method="GET", path="/api/upgradestatusinfo")
    assert entry["spec"] == "avi/UpgradeStatusInfo.yaml"  # not Alert.yaml


def test_exact_resource_beats_substring_cousin():
    """'virtual service' must rank /api/virtualservice above
    /api/debugvirtualservice, which merely contains it."""
    results = specs.search("list virtual services", target="avi", limit=3)["results"]
    assert results[0]["path"] == "/api/virtualservice"


# --- round 4: addresses are site-local, never checked in -------------------

def test_no_appliance_address_is_hardcoded():
    """The repo is public. An address belongs in hosts.json or an env var, so
    a literal IP reappearing in the registry is a leak, not a convenience."""
    import re as _re
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "src" / "vcf_mcp" / "config.py").read_text()
    assert not _re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", source)


def test_host_env_var_name_survives_a_dash():
    """vsan-dp is the only target whose name is not a valid env-var fragment;
    getting this wrong silently ignores the override."""
    from vcf_mcp import config
    assert config.host_env_var("vsan-dp") == "VCF_MCP_VSAN_DP_HOST"
    assert config.host_env_var("nsx") == "VCF_MCP_NSX_HOST"


def test_unconfigured_target_names_what_to_set():
    """An unset address must fail before a request is built against
    'https:///v1/...', and the error has to say which knob to turn."""
    import dataclasses
    import pytest
    from vcf_mcp import config

    blank = dataclasses.replace(config.get_target("ops"), host="")
    with pytest.raises(RuntimeError) as excinfo:
        config.require_host(blank)
    assert "VCF_MCP_OPS_HOST" in str(excinfo.value)
    assert "hosts.example.json" in str(excinfo.value)
