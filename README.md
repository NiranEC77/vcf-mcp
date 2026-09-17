# vcf-mcp

An MCP server that gives an LLM agent full API access to a VMware Cloud
Foundation 9.1 estate.

It connects to seven appliances — SDDC Manager, VCF Installer, vCenter, NSX,
Avi Load Balancer, VCF Operations and vSAN Data Protection — and exposes their
**8,931 API operations through eight tools**. It handles authentication for
each appliance, resolves request paths, follows async tasks, and records every
mutating call.

It speaks MCP over stdio, so it works with any MCP client: Claude Code, Claude
Desktop, Cursor, Windsurf, Zed, Continue, or your own agent built on an MCP
SDK. There is nothing to install — point a client at:

```
uvx --from git+https://github.com/NiranEC77/vcf-mcp vcf-mcp
```

---

## Contents

- [How it works](#how-it-works) · [Install](#install) · [Configure](#configure) ·
  [Connect an agent](#connect-an-agent) · [Tools](#tools) ·
  [Targets](#targets) · [Environment variables](#environment-variables) ·
  [Write safety](#write-safety) · [Tests](#tests) ·
  [VCF 9.1 behaviour](#vcf-91-behaviour)

---

## How it works

**One tool per endpoint does not scale.** 8,931 tool schemas would exhaust the
context window before the agent asked its first question, and tool selection
degrades badly past a few dozen options.

Instead, the OpenAPI specs are indexed once at startup into a compact record
per operation (method, path, summary, operationId, tags). The agent then works
the way an engineer does — search, read the schema, dry-run, execute, follow
the task:

```
vcf_search_api("commission hosts")    ->  POST /v1/hosts  (commissionHosts)
vcf_describe_api(operation_id=...)    ->  required fields, types, responses
vcf_validate(target, path, body)      ->  dry-runs the spec, changes nothing
vcf_call(target, method, path, body)  ->  executes it, auth handled
vcf_task(target, task_id)             ->  follows the async result
```

Context cost stays fixed however many operations exist. Adding an appliance
means adding a spec file and a registry entry, not a new tool.

**Authentication** is per-appliance and automatic. Each target has its own
scheme (see [Targets](#targets)); the server mints a token on first use,
caches it in memory for the process lifetime, never writes it to disk, and
re-mints it automatically on a 401/403.

**Spec handling.** Both dialects are parsed: OpenAPI 3.x (SDDC Manager,
Installer, Operations, vCenter) and Swagger 2.0 (NSX). Base paths differ per
spec — `/suite-api` for Operations, `/api` for vCenter, `/policy/api/v1` for
NSX policy — and are resolved at index time, so paths returned by search are
real request paths you can pass straight to `vcf_call`.

---

## Install

Requires network access to the appliances. Nothing else — `uvx` fetches,
builds and runs the server in one step, and the API specs ship inside the
package, so there is no separate download:

```bash
uvx --from git+https://github.com/NiranEC77/vcf-mcp vcf-mcp check
```

That is also the command an MCP client should launch (see
[Connect an agent](#connect-an-agent)). `uvx` comes with
[uv](https://docs.astral.sh/uv/); install it with
`curl -LsSf https://astral.sh/uv/install.sh | sh`.

To install it as a normal command instead:

```bash
uv tool install git+https://github.com/NiranEC77/vcf-mcp    # then: vcf-mcp
pipx install git+https://github.com/NiranEC77/vcf-mcp       # same, via pipx
pip install git+https://github.com/NiranEC77/vcf-mcp        # into a venv
```

Or work from a clone (Python 3.10+):

```bash
git clone https://github.com/NiranEC77/vcf-mcp.git && cd vcf-mcp
uv venv --python 3.12 && uv pip install -e .
```

A clone keeps its config and logs in the repo directory; an installed copy
uses `~/.config/vcf-mcp/` and `~/.local/state/vcf-mcp/`. Either way the
environment variables below override both.

---

## Configure

### 1. Appliance addresses

No addresses are stored in this repo. Create a `hosts.json` — in
`~/.config/vcf-mcp/` for an installed copy, or the repo root for a clone
(where it is gitignored), or anywhere if you set `VCF_MCP_HOSTS_FILE`:

```json
{
  "hosts": {
    "sddc":      "sddc-manager.example.local",
    "installer": "vcf-installer.example.local",
    "vcenter":   "vcenter.example.local",
    "nsx":       "nsx-vip.example.local",
    "ops":       "vcf-ops.example.local",
    "avi":       "avi-controller.example.local",
    "vsan-dp":   "vcenter.example.local"
  }
}
```

Any target can instead be set with `VCF_MCP_<TARGET>_HOST`, which wins over the
file. `vsan-dp` is served by the vCenter appliance, so it takes the same
address as `vcenter`. Targets you leave out are reported as unconfigured by
`vcf_targets` rather than called.

### 2. Credentials

Passwords are read from a `.env` file — point `VCF_MCP_ENV_FILE` at whichever
file is already your rotation point, or create one next to `hosts.json`:

```bash
NSX_ADMIN_PASSWORD=...
SDDC_MANAGER_PASSWORD=...
VCF_INSTALLER_PASSWORD=...
NESTED_VCSA_PASSWORD=...
VCF_APPLIANCE_PASSWORD=...
```

Each target tries its own ordered subset of these keys; empty values and
anything containing `CHANGEME` are skipped. A single target can be overridden
with `VCF_MCP_<TARGET>_PASSWORD`. Nothing is copied into the repo, and no tool
ever returns a secret — failures name the *key* they looked for, never a value.

Authentication is capped at **3 attempts per target**
(`config.MAX_AUTH_ATTEMPTS`). vSphere SSO locks accounts after repeated
failures, so trying every password in the file is not a harmless fallback.

**Avi has no standing credential anywhere.** Its admin password is
VCF-generated and lives only in SDDC Manager's credential store. The server
fetches it at auth time (`GET /v1/credentials`, resourceType `NSX_ALB`), uses
it to log in, and never returns, logs or persists it. Set
`VCF_MCP_AVI_PASSWORD` to override this for a controller VCF does not manage.
Avi rejects HTTP Basic outright — only the session flow works.

### 3. Verify

```bash
vcf-mcp index    # index all operations (~8s, then cached to disk)
vcf-mcp check    # print every target and whether it answers
```

Prefix with `uvx --from git+https://github.com/NiranEC77/vcf-mcp` if you have
not installed it. `check` names any target whose address is still unset.

---

## Connect an agent

The server is a stdio process: run `vcf-mcp` with no arguments (equivalently,
`python -m vcf_mcp`) and it speaks MCP on stdin/stdout.

### Any MCP client

Most clients read the same JSON shape. Add this to the client's MCP config —
no prior install needed, `uvx` handles it:

```json
{
  "mcpServers": {
    "vcf": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/NiranEC77/vcf-mcp", "vcf-mcp"],
      "env": {
        "VCF_MCP_HOSTS_FILE": "/absolute/path/to/hosts.json",
        "VCF_MCP_ENV_FILE": "/absolute/path/to/your/.env"
      }
    }
  }
}
```

If you installed it already, replace those two fields with
`"command": "vcf-mcp"` (or the absolute path to the executable, which some
clients require because they do not inherit your shell's `PATH`).

`.mcp.example.json` in this repo is that file, ready to copy. Where each client
keeps its config:

| Client | Config location |
|---|---|
| Claude Code | `.mcp.json` in the project, or `claude mcp add` (below) |
| Claude Desktop | `claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Zed | `settings.json`, under `context_servers` |
| Continue | `config.yaml`, under `mcpServers` |

### Claude Code

```bash
claude mcp add vcf \
  --env VCF_MCP_HOSTS_FILE=/absolute/path/to/hosts.json \
  --env VCF_MCP_ENV_FILE=/absolute/path/to/your/.env \
  -- uvx --from git+https://github.com/NiranEC77/vcf-mcp vcf-mcp
```

### Your own agent

Any MCP SDK can launch it as a subprocess. With the Python SDK:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(
    command="uvx",
    args=["--from", "git+https://github.com/NiranEC77/vcf-mcp", "vcf-mcp"],
    env={"VCF_MCP_HOSTS_FILE": "/absolute/path/to/hosts.json"},
)

async with stdio_client(params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool("vcf_search_api", {"query": "commission hosts"})
```

The server advertises `read_only` and `destructive` annotations per tool, so a
client that gates writes can do so without a hardcoded tool list.

---

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `vcf_targets` | `check_reachability=true` | Every appliance: name, product, address, auth scheme, operation count, whether it answers |
| `vcf_search_api` | `query`, `target?`, `method?`, `limit=25`, `include_deprecated=false` | Ranked operations with method, full path, summary, operationId |
| `vcf_describe_api` | `operation_id?` or `method`+`path`, `target?`, `depth=3`, `max_properties=60` | Path/query parameters, resolved request body schema with required fields, response schemas |
| `vcf_validate` | `target`, `path`, `body?`, `wait_seconds=120` | `validated` true/false plus each failed check — executes nothing |
| `vcf_call` | `target`, `method`, `path`, `query?`, `body?`, `timeout?`, `max_response_chars=20000` | `count` + `summary` + slim `items` when the body is a list (full length, even if truncated); task id for async operations |
| `vcf_task` | `target`, `task_id`, `wait_seconds=0`, `poll_interval=5.0` | Task status and, on failure, which subtask failed and why |
| `vcf_inventory` | `targets?`, `per_section_limit=25` | Domains, clusters, hosts, gateways and alerts in one snapshot |
| `vcf_audit` | `limit=50` | Recent mutating calls made through this server |

`vcf_call` is annotated as destructive; every other tool is annotated read-only.

Typical sequence for a change: `vcf_search_api` → `vcf_describe_api` →
`vcf_validate` → `vcf_call` → `vcf_task`.

---

## Targets

| Target | Product | Authentication | Operations |
|---|---|---|---|
| `sddc` | SDDC Manager | `POST /v1/tokens` → Bearer | 500 |
| `installer` | VCF Installer | `POST /v1/tokens` → Bearer | 57 |
| `vcenter` | vCenter Server | `POST /api/session` → `vmware-api-session-id` | 1,367 |
| `nsx` | NSX Manager (VIP) | HTTP Basic | 5,182 |
| `avi` | Avi Load Balancer (NSX ALB) | `POST /login` → session cookies + `X-CSRFToken` | 1,233 |
| `ops` | VCF Operations | `POST /suite-api/api/auth/token/acquire` → `vRealizeOpsToken` | 527 |
| `vsan-dp` | vSAN Data Protection | vCenter session | 65 |

Every scheme above was verified against a live 9.1 estate.

---

## Environment variables

| Variable | Effect |
|---|---|
Defaults differ between a clone and an installed copy, as noted:

| Variable | Effect | Default (clone → installed) |
|---|---|---|
| `VCF_MCP_HOSTS_FILE` | Path to the addresses file | `./hosts.json` → `~/.config/vcf-mcp/hosts.json` |
| `VCF_MCP_<TARGET>_HOST` | Override one address, e.g. `VCF_MCP_NSX_HOST` | — |
| `VCF_MCP_ENV_FILE` | Path to the credentials `.env` | `./.env` → `~/.config/vcf-mcp/.env` |
| `VCF_MCP_<TARGET>_PASSWORD` | Override one target's password, e.g. `VCF_MCP_SDDC_PASSWORD` | — |
| `VCF_MCP_INSTALLER_CREDS` | Installer's generated credentials file | alongside the `.env` |
| `VCF_MCP_VERIFY_TLS=1` | Enforce TLS verification | off — appliances present self-signed certs |
| `VCF_MCP_AUDIT_LOG` | Where mutations are recorded | `./logs/vcf-mcp-audit.jsonl` → `~/.local/state/vcf-mcp/vcf-mcp-audit.jsonl` |
| `VCF_MCP_SPEC_DIR` | Spec source directory | `./specs` → the copy bundled in the package |
| `VCF_MCP_CACHE_DIR` | Index cache directory | `~/.cache/vcf-mcp` |

---

## Write safety

**There is no write gate.** Any operation the API allows — including
`DELETE /v1/domains/{id}` and host decommission — executes immediately when the
agent calls it. This is deliberate: the server does not try to second-guess
which operations are safe.

What exists instead is a record. Every POST/PATCH/PUT/DELETE is appended to
`logs/vcf-mcp-audit.jsonl` with target, path, status, duration and a
**redacted** body — anything keyed like a password, token, secret or credential
is replaced before the line is written. `vcf_audit` reads it back, including
changes made by earlier sessions.

If you want a gate, `client.request()` is the single chokepoint that every call
in the server passes through.

---

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

36 offline tests, no appliance required. Each pins a bug found during the
build: camelCase tokenisation, plural stemming, `$ref` cycle handling,
truncation across differently-named collections, secret redaction, task-id
detection, case-insensitive task states, and the rule that no appliance address
is ever hardcoded into the registry.

---

## Specs

Vendored from [vmware/vcf-api-specs](https://github.com/vmware/vcf-api-specs)
at commit `3949fc3` (2026-05-13), version `9.1.0.0`. Provenance in
`specs/SPECS-PROVENANCE.txt`.

The 170 Avi object specs in `specs/avi/` were downloaded from an Avi
controller's own swagger endpoint (`/swagger/<Object>.yaml`), so they are
version-matched to the deployed build by construction. Avi's per-object files
re-declare related objects' paths; the index deduplicates them and keeps the
declaration from the file named after the resource.

---

## VCF 9.1 behaviour

Discovered while building against a live estate, and encoded in the server:

- `POST /v1/system/prechecks` is gone; the replacement is
  `POST /v1/system/health-summary` (`startHealthCheck`).
- The whole `/v1/edge-clusters` family on SDDC Manager is deprecated, including
  `updateEdgeCluster` (`PATCH /v1/edge-clusters/{id}`).
- Deprecated operations are hidden from search unless `include_deprecated` is
  set. Well-scoring ones are still reported under `hidden_deprecated`, so a
  legacy path found in old documentation is identified as legacy rather than
  appearing not to exist.
- SDDC Manager returns task status as `"Successful"`, not `"SUCCESSFUL"`;
  `vcf_task` compares case-insensitively.
- vCenter (vAPI) specs declare enums as prose ("Possible values: ...").
  `vcf_describe_api` lifts them into a real `enum` list.
- NSX often has the strictest password complexity rules of the fleet, so an
  estate is frequently built with one password NSX accepts. `NSX_ADMIN_PASSWORD`
  is therefore tried first for several targets.
