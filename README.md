# vcf-mcp

An MCP server that lets a Claude Code session configure and manage a VMware
Cloud Foundation 9.1 estate.

It talks to seven appliances — SDDC Manager, VCF Installer, vCenter, NSX,
Avi Load Balancer, VCF Operations and vSAN Data Protection — and exposes
**8,931 API operations through eight tools**.

## Why eight tools and not 8,931

One MCP tool per endpoint is the obvious design and it does not work. The
schemas alone would exhaust the context window before the first question got
asked, and tool selection degrades badly past a few dozen options.

So the OpenAPI specs are indexed once into a compact record per operation, and
the agent works the way a person does:

```
vcf_search_api("commission hosts")   ->  POST /v1/hosts  (commissionHosts)
vcf_describe_api(operation_id=...)   ->  required fields, types, responses
vcf_validate(target, path, body)     ->  dry-runs the spec, changes nothing
vcf_call(target, method, path, body) ->  runs it, handles auth
vcf_task(target, task_id)            ->  follows the async result
```

Cost stays fixed no matter how many operations exist. Adding a new appliance
means adding a spec file and a registry entry — not a new tool.

## Tools

| Tool | Purpose |
|---|---|
| `vcf_targets` | Which appliances exist, their versions, whether they answer |
| `vcf_search_api` | Find operations by intent across all indexed specs |
| `vcf_describe_api` | Full resolved signature: params, body schema, responses |
| `vcf_validate` | Dry-run a spec against its `/validations` twin — no execution |
| `vcf_call` | Execute any operation; auth, retry and audit handled |
| `vcf_task` | Poll or wait on a long-running task, with failed subtasks |
| `vcf_inventory` | One snapshot of the whole estate |
| `vcf_audit` | Every mutating call this server has made |

Only `vcf_call` is annotated as a write tool; the rest are marked read-only.

## Targets

| Target | Product | Auth (verified live) | Ops |
|---|---|---|---|
| `sddc` | SDDC Manager | `POST /v1/tokens` → Bearer | 500 |
| `installer` | VCF Installer | `POST /v1/tokens` → Bearer | 57 |
| `vcenter` | vCenter Server | `POST /api/session` → `vmware-api-session-id` | 1,367 |
| `nsx` | NSX Manager (VIP) | HTTP Basic | 5,182 |
| `avi` | Avi Load Balancer (NSX ALB) | `POST /login` → session cookies + `X-CSRFToken` | 1,233 |
| `ops` | VCF Operations | `POST /suite-api/api/auth/token/acquire` → `vRealizeOpsToken` | 527 |
| `vsan-dp` | vSAN Data Protection | vCenter session | 65 |

Addresses are site-specific and are **not** in this repo. Copy
`hosts.example.json` to `hosts.json` and fill in your estate, or set
`VCF_MCP_<TARGET>_HOST` per target (the env var wins). `vsan-dp` is served by
the vCenter appliance, so it takes the same address as `vcenter`. A target with
no address is reported as unconfigured by `vcf_targets` rather than called.

Tokens are cached in memory for the process lifetime, never written to disk,
and re-minted automatically on a 401/403.

**Avi has no standing credential anywhere.** Its admin password is VCF-generated
and lives only in SDDC Manager's credential store; the server fetches it at
auth time (`GET /v1/credentials`, resourceType `NSX_ALB`), uses it to log in,
and never returns, logs, or persists it. `VCF_MCP_AVI_PASSWORD` overrides this
for a non-VCF-managed controller. Avi rejects HTTP Basic outright — only the
session flow works.

## Install

```bash
uv venv --python 3.12
uv pip install -e .
cp hosts.example.json hosts.json   # then put your estate's addresses in it
.venv/bin/python -m vcf_mcp index    # build the operation index (~8s, cached)
.venv/bin/python -m vcf_mcp check    # authenticate to every target
```

## Register with Claude Code

From the session that should manage VCF:

```bash
claude mcp add vcf -- /path/to/vcf-mcp/.venv/bin/python -m vcf_mcp
```

Or copy `.mcp.example.json` to `.mcp.json` in the project the other session
runs in, filling in the absolute paths. `.mcp.json` is gitignored because it
carries machine-local paths.

## Credentials

Read from a `.env` file — point `VCF_MCP_ENV_FILE` at whatever is already the
rotation point for the estate (it defaults to `.env` beside this README).
Nothing is copied into this repo and no tool ever returns a secret; failures
name the *key* they looked for, never a value.

Keys used, in the order each target tries them: `NSX_ADMIN_PASSWORD`,
`SDDC_MANAGER_PASSWORD`, `VCF_APPLIANCE_PASSWORD`, `VCF_INSTALLER_PASSWORD`,
`NESTED_VCSA_PASSWORD`. Empty values and anything containing `CHANGEME` are
skipped.

Override with:

| Variable | Effect |
|---|---|
| `VCF_MCP_ENV_FILE` | Use a different .env |
| `VCF_MCP_HOSTS_FILE` | Use a different hosts file (default `hosts.json`) |
| `VCF_MCP_<TARGET>_HOST` | Override one address (e.g. `VCF_MCP_NSX_HOST`) |
| `VCF_MCP_INSTALLER_CREDS` | Path to the generated installer credentials file |
| `VCF_MCP_<TARGET>_PASSWORD` | Override one target (e.g. `VCF_MCP_SDDC_PASSWORD`) |
| `VCF_MCP_VERIFY_TLS=1` | Enforce TLS verification (off by default: self-signed certs, island network) |
| `VCF_MCP_AUDIT_LOG` | Where mutations are recorded (default `logs/vcf-mcp-audit.jsonl`) |
| `VCF_MCP_SPEC_DIR` / `VCF_MCP_CACHE_DIR` | Spec source and index cache |

Authentication attempts are capped at **3 per target** (`config.MAX_AUTH_ATTEMPTS`).
vSphere SSO locks accounts after repeated failures, so trying every password in
the .env is not a harmless fallback.

## Write safety

This server has **no write gate** — that was a deliberate decision. Any
operation the API allows, including `DELETE /v1/domains/{id}` and host
decommission, can be called immediately.

What exists instead is a record: every POST/PATCH/PUT/DELETE is appended to
`logs/vcf-mcp-audit.jsonl` with target, path, status, duration and a
**redacted** body (anything keyed like a password, token, secret or credential
is replaced before writing). `vcf_audit` reads it back.

To add a gate later, `client.request()` is the single chokepoint — every call
in the server goes through it.

## Specs

Vendored from [github.com/vmware/vcf-api-specs](https://github.com/vmware/vcf-api-specs)
at commit `3949fc3` (2026-05-13), version `9.1.0.0` — matching the live estate
build `9.1.0.0100`. Provenance in `specs/SPECS-PROVENANCE.txt`.

The 170 Avi object specs in `specs/avi/` were downloaded from the controller's
own swagger endpoint (`/swagger/<Object>.yaml`), so they are version-matched to
the deployed build by construction. Avi's per-object files re-declare related
objects' paths; the index deduplicates and keeps the declaration from the file
named after the resource.

Both dialects are handled: OpenAPI 3.x (SDDC Manager, Installer, Operations,
vCenter) and Swagger 2.0 (NSX). Base paths differ per spec — `/suite-api` for
Operations, `/api` for vCenter, `/policy/api/v1` for NSX policy — and are
resolved at index time, so paths returned by search are the real request paths.

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

36 offline tests, no appliance needed. Each pins a bug found during the build:
camelCase tokenisation, plural stemming, `$ref` cycle handling, truncation
across differently-named collections, secret redaction, task-id detection,
case-insensitive task states, and the rule that no appliance address is ever
hardcoded into the registry.

## Notes from building against the live estate

- `updateEdgeCluster` (`PATCH /v1/edge-clusters/{id}`) is **deprecated in 9.1**.
  Deprecated operations are hidden from search unless you ask for them.
- `POST /v1/system/prechecks` is gone in 9.1; the replacement is
  `POST /v1/system/health-summary` (`startHealthCheck`).
- SDDC Manager returns task status as `"Successful"`, not `"SUCCESSFUL"`.
- `SDDC_MANAGER_PASSWORD` in the lab `.env` is stale; `NSX_ADMIN_PASSWORD` is
  the value the fleet is actually built with, so it is tried first.
- The whole `/v1/edge-clusters` family on SDDC Manager is deprecated in 9.1.
- vCenter (vAPI) specs declare enums as prose ("Possible values: ...");
  `vcf_describe_api` lifts them into a real `enum` list.
- Search reports well-scoring deprecated matches under `hidden_deprecated`
  instead of silently dropping them, so a legacy path found in old docs is
  identified as legacy rather than appearing to not exist.
