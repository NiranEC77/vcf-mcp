# Changelog

Terse, dated. Component — change — verification.

## 2026-09-20

- tools: **each domain job is a set of tools** — VM management has list/get/power/start/stop/reset/suspend; network has networks/segments/gateways; storage has list/get/policy; metrics has alerts/snapshot; not one tool per job — verified `pytest tests/ -q`
- version **0.3.1**
- tools: **four domain jobs** — `vcf_vms` (list/get/start/stop/reset/suspend), `vcf_networks`, `vcf_storage`, `vcf_metrics`; generic search/call stay; a grant can name one job or full access — verified `pytest tests/test_offline.py -q`
- version **0.3.0**
- http: **Streamable HTTP mode in the package** (`$PORT` or `vcf-mcp serve-http`); `pip install "vcf-mcp[http]"`; refuses to start with no bearer; `/health`; RFC 9728 metadata; `WWW-Authenticate` on 401 — verified local smoke: health 200, metadata 200, no bearer 401, junk JWT 401, static read token initialize 200
- http: **OAuth resource server** (`oauth_bearer.py`): issuer JWKS via RFC 8414 discovery or `VCF_MCP_OAUTH_JWKS_URI`; `aud` must name `VCF_MCP_RESOURCE_URL` or `VCF_MCP_OAUTH_AUDIENCES`; tool-name and `tools` scopes decide read/admin — verified `pytest tests/test_http_auth.py -q`
- http: **gateway job scopes are a grant** — a token carrying `urn:iam:agent:intent:<job>` (prefix `VCF_MCP_OAUTH_INTENT_PREFIX`) is admin; the gateway already mapped tool → job → policy and strips the rest; the server no longer re-checks tool names and 401s an intent-only token — verified `pytest tests/ -q` 58 passed
- config: **flat hosted layout** (`<app>/vcf_mcp` with `specs/` beside it) detected as a checkout — verified `PYTHONPATH=src` smoke above
- client: **`VCF_MCP_AUDIT_LOG=/dev/stdout` / `/dev/stderr`** write to the stream instead of `mkdir("/dev")` — verified unit path in `test_http_auth`
- version **0.2.0**

## 2026-09-17

- vcf_call: **list replies lead with `count` + `summary` + slim `items`** — fat vSAN objects no longer become a 20k clipped string that hides the number — verified `pytest tests/test_offline.py -q` 43 passed (`test_call_leads_with_count_and_slims_items`, `test_fit_does_not_clip_a_list_item_to_an_opaque_string`)

## 2026-08-30

- vcf_call: **list replies include `count`** (full length, before `_fit` truncates) so an agent does not count JSON fields — verified `pytest tests/test_offline.py -q` (`test_count_items_*`, `test_count_survives_truncation`)
