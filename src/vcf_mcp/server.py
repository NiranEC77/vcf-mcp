"""MCP server exposing VMware Cloud Foundation to any MCP client.

Design note for anyone extending this: resist adding a tool per VCF feature.
The estate has ~7,700 operations across six appliances; the value of this
server is that it stays a handful of tools no matter how many. New capability belongs
in the spec index or the target registry, not in a new tool.

Every tool body is synchronous (HTTP, file I/O) and is run on a worker thread
so a slow appliance -- and VCF has many -- cannot stall the event loop.
"""
from __future__ import annotations

import functools
import logging
from typing import Any

import anyio

try:  # MCP SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - SDK 1.x calls the same thing FastMCP
    from mcp.server.fastmcp import FastMCP as _Server

try:
    from mcp.types import ToolAnnotations
except ImportError:  # pragma: no cover
    ToolAnnotations = None  # type: ignore[assignment]

from . import __version__, tools

mcp = _Server(
    "vcf",
    version=__version__,
    instructions=(
        "Configure and manage a VMware Cloud Foundation 9.1 estate. Domain "
        "jobs: vcf_vms (list, get, start, stop, reset, suspend), "
        "vcf_networks, vcf_storage, vcf_metrics. A grant can name one of "
        "those jobs, or full access. Start with vcf_targets or vcf_inventory "
        "for a snapshot. For anything else: vcf_search_api, vcf_describe_api, "
        "vcf_validate, then vcf_call. Writes take effect immediately. Follow "
        "a returned task id with vcf_task."
    ),
)


def _hints(*, read_only: bool = False, destructive: bool = False):
    """Tool annotations, when the installed SDK supports them.

    MCP SDK 2.x names these fields in snake_case; 1.x used camelCase. Build
    whichever the installed model actually declares instead of assuming, so
    the hints are really set rather than silently dropped.
    """
    if ToolAnnotations is None:  # pragma: no cover
        return {}
    wanted = {
        "read_only_hint": read_only,
        "destructive_hint": destructive,
        "idempotent_hint": read_only,
        "open_world_hint": True,
    }
    fields = set(getattr(ToolAnnotations, "model_fields", {}) or {})
    if fields and "read_only_hint" not in fields:  # pragma: no cover - SDK 1.x
        wanted = {
            "".join(w.capitalize() if i else w for i, w in enumerate(key.split("_"))): value
            for key, value in wanted.items()
        }
    return {"annotations": ToolAnnotations(**wanted)}


async def _run(func, /, **kwargs) -> Any:
    """Call a blocking tool implementation off the event loop.

    Errors are returned as data rather than raised: an agent recovers far
    better from `{"error": "unknown target 'nsxt'..."}` than from a stack
    trace, and the message carries the fix.
    """
    try:
        return await anyio.to_thread.run_sync(functools.partial(func, **kwargs))
    except Exception as exc:  # surfaced to the caller, never swallowed
        return {"error": f"{type(exc).__name__}: {exc}"}


@mcp.tool(**_hints(read_only=True))
async def vcf_targets(check_reachability: bool = True) -> Any:
    """List every VCF appliance this server can talk to.

    Start here. Returns each target's name, product, address, auth scheme,
    how many API operations it serves, and whether it is currently answering.
    The `target` name from this list is what every other tool expects.
    """
    return await _run(tools.targets, check_reachability=check_reachability)


@mcp.tool(**_hints(read_only=True))
async def vcf_search_api(
    query: str,
    target: str | None = None,
    method: str | None = None,
    limit: int = 25,
    include_deprecated: bool = False,
) -> Any:
    """Find VCF API operations by intent, across ~7,700 indexed operations.

    Search the way you would describe the task -- "commission hosts", "rotate
    passwords", "expand cluster", "list segments" -- rather than guessing a
    path. Results are ranked and include method, full request path, summary
    and operationId.

    Args:
        query: What you want to do, in plain words.
        target: Restrict to one appliance (sddc, vcenter, nsx, ops,
            installer, vsan-dp). Strongly recommended when you know it.
        method: Restrict to GET/POST/PATCH/PUT/DELETE.
        limit: Maximum results (default 25).
        include_deprecated: Include operations VCF 9.1 marks deprecated.
    """
    return await _run(
        tools.search_api,
        query=query,
        target=target,
        method=method,
        limit=limit,
        include_deprecated=include_deprecated,
    )


@mcp.tool(**_hints(read_only=True))
async def vcf_describe_api(
    target: str | None = None,
    operation_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
    depth: int = 3,
    max_properties: int = 60,
) -> Any:
    """Show the full signature of one API operation before calling it.

    Identify the operation either by `operation_id` (from vcf_search_api) or
    by `method` plus `path`. Returns path/query parameters, the resolved
    request body schema with required fields marked, and response schemas.

    Always do this before a POST/PATCH/PUT -- VCF request bodies are large
    and unforgiving, and the schema names the required fields.

    Args:
        depth: How deep to expand nested schemas (1-6, default 3). Raise it
            when a nested object shows "truncated".
        max_properties: Cap properties rendered per object (default 60).
    """
    return await _run(
        tools.describe_api,
        target=target,
        operation_id=operation_id,
        method=method,
        path=path,
        depth=depth,
        max_properties=max_properties,
    )


@mcp.tool(**_hints(destructive=True))
async def vcf_call(
    target: str,
    method: str,
    path: str,
    query: dict | None = None,
    body: Any = None,
    timeout: float | None = None,
    max_response_chars: int = tools.DEFAULT_MAX_CHARS,
) -> Any:
    """Call a VCF API operation. Authentication is handled for you.

    This performs real operations against real infrastructure. Reads are
    safe; POST/PATCH/PUT/DELETE change the estate, and some are irreversible
    (decommissioning a host, deleting a workload domain). Every mutating call
    is recorded to the audit log. Check vcf_describe_api first when writing.

    Long-running operations return HTTP 202 and a task id -- follow it with
    vcf_task rather than assuming success.

    When the appliance returns a list, the result leads with ``count`` and
    ``summary`` (full length, before any truncation) plus slim ``items``.
    Say that number. Do not count objects or fields in ``body``.

    Args:
        target: Appliance name from vcf_targets.
        method: GET, POST, PATCH, PUT or DELETE.
        path: Full request path including any base prefix, exactly as
            vcf_search_api reports it (e.g. "/v1/hosts",
            "/policy/api/v1/infra/segments/web-seg"). Substitute real ids for
            {placeholders}.
        query: Query parameters as an object.
        body: JSON request body.
        timeout: Seconds to wait (VCF operations can be slow; default 300).
        max_response_chars: Shrink oversized responses to fit (default 20000).
    """
    # HTTP mode only: stdio has no bearer tokens and capability stays "admin".
    if CAPABILITY.get() == "read" and method.upper() not in ("GET", "HEAD", "OPTIONS"):
        return {
            "ok": False,
            "denied": True,
            "error": (
                f"{method.upper()} needs the admin capability; this session's "
                "bearer token only allows reads (GET/HEAD)."
            ),
        }
    return await _run(
        tools.call,
        target=target,
        method=method,
        path=path,
        query=query,
        body=body,
        timeout=timeout,
        max_response_chars=max_response_chars,
    )


@mcp.tool(**_hints(read_only=True))
async def vcf_task(
    target: str, task_id: str, wait_seconds: int = 0, poll_interval: float = 5.0
) -> Any:
    """Check, or wait on, a long-running VCF task.

    Most mutations return a task id instead of a result. This reports the
    task's current status and, when it fails, which subtask failed and why.

    Args:
        target: sddc or installer.
        task_id: The id returned by vcf_call.
        wait_seconds: Poll until the task reaches a terminal state or this
            many seconds elapse. 0 (default) checks once and returns.
    """
    return await _run(
        tools.task,
        target=target,
        task_id=task_id,
        wait_seconds=wait_seconds,
        poll_interval=poll_interval,
    )


@mcp.tool(**_hints(read_only=True))
async def vcf_validate(
    target: str,
    path: str,
    body: Any = None,
    wait_seconds: int = 120,
) -> Any:
    """Test a spec against VCF's validation endpoint WITHOUT executing it.

    SDDC Manager and the Installer pair most mutating endpoints with a
    validation twin that takes the same request body and checks it end to end
    -- POST /v1/clusters/validations for POST /v1/clusters, and so on. This
    is the safe way to iterate on a spec before committing it.

    Give the real path (e.g. "/v1/hosts") or the validation path directly;
    the twin is resolved automatically, run, and polled to completion.
    Returns validated true/false plus each failed check with its error.

    Targets without the /validations convention (vCenter uses ?action=check
    operations) get a list of the nearest check-style operations instead.

    Args:
        target: Appliance name from vcf_targets (sddc and installer have
            the richest validation surface).
        path: The operation you intend to run, or its /validations path.
        body: The same JSON body you would give the real operation.
        wait_seconds: How long to poll for the validation verdict.
    """
    return await _run(
        tools.validate, target=target, path=path, body=body, wait_seconds=wait_seconds
    )


@mcp.tool(**_hints(read_only=True))
async def vcf_inventory(targets: list[str] | None = None, per_section_limit: int = 25) -> Any:
    """Snapshot the estate: domains, clusters, hosts, gateways, alerts.

    One call that answers "what have I got?" across SDDC Manager, vCenter,
    NSX and Operations. Unreachable appliances are reported inline rather
    than failing the whole snapshot.

    Args:
        targets: Restrict to specific appliances (default: all with a recipe).
        per_section_limit: Items shown per section before summarising.
    """
    return await _run(
        tools.inventory, targets_wanted=targets, per_section_limit=per_section_limit
    )


@mcp.tool(**_hints(read_only=True))
async def vcf_audit(limit: int = 50) -> Any:
    """Show recent mutating calls made through this server.

    Every POST/PATCH/PUT/DELETE is logged with target, path, status and a
    redacted body. Use it to answer "what did I change?" -- including
    changes made by an earlier session.
    """
    return await _run(tools.audit, limit=limit)


@mcp.tool(**_hints(destructive=True))
async def vcf_vms(action: str = "list", vm: str | None = None) -> Any:
    """Manage virtual machines.

    list or count: every VM and the number. get: one VM. power: current
    power state. start, stop, reset, suspend: change power now. Pass vm
    from the list. This is VM work, not networks or storage.
    """
    return await _run(tools.vms, action=action, vm=vm)


@mcp.tool(**_hints(read_only=True))
async def vcf_networks(action: str = "list") -> Any:
    """List networks: vCenter port groups and NSX segments and gateways.

    This is network work, not VMs. Use list. The result leads with count.
    """
    return await _run(tools.networks, action=action)


@mcp.tool(**_hints(read_only=True))
async def vcf_storage(action: str = "list") -> Any:
    """List datastores on vCenter.

    This is storage work, not VMs. Use list. The result leads with count.
    """
    return await _run(tools.storage, action=action)


@mcp.tool(**_hints(read_only=True))
async def vcf_metrics(action: str = "alerts") -> Any:
    """Collect live metrics from VCF Operations.

    alerts: current alerts and the count. This is metrics, not VM or
    network management.
    """
    return await _run(tools.metrics, action=action)


# ---------------------------------------------------------------------------
# Streamable HTTP. Stdio stays the default for desktop clients; HTTP is for a
# hosted copy (a PaaS app, a container) that agents reach over the network.
# ---------------------------------------------------------------------------

import os  # noqa: E402
import secrets  # noqa: E402
from contextvars import ContextVar  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402

from . import oauth_bearer  # noqa: E402

# Per-request capability set by the HTTP gate. "admin" may mutate; "read"
# may only GET/HEAD. Stdio never sets it, so the default applies.
CAPABILITY: ContextVar[str] = ContextVar("capability", default="admin")

READ_TOOLS = (
    "vcf_targets",
    "vcf_search_api",
    "vcf_describe_api",
    "vcf_validate",
    "vcf_inventory",
    "vcf_audit",
    "vcf_networks",
    "vcf_storage",
    "vcf_metrics",
)
WRITE_TOOLS = ("vcf_call", "vcf_task", "vcf_vms")


def _default_resource_url() -> str:
    return oauth_bearer.resource_url(default="http://127.0.0.1:8080/mcp")


def _classify_token(presented: str | None) -> str | None:
    """Map a bearer token -> 'admin' | 'read' | None.

    Static tokens first (constant-time compare). Then a JWT from the OAuth
    issuer, if one is configured: tool-name scopes, the blanket ``tools``
    scope, or a gateway-issued intent scope (see ``oauth_bearer``).
    """
    if not presented:
        return None
    admin = os.environ.get("VCF_ADMIN_TOKEN", "")
    read = os.environ.get("VCF_READ_TOKEN", "")
    if admin and secrets.compare_digest(presented, admin):
        return "admin"
    if read and secrets.compare_digest(presented, read):
        return "read"
    if not oauth_bearer.enabled():
        return None
    return oauth_bearer.classify(
        presented,
        default_resource=_default_resource_url(),
        read_scopes=["tools", *READ_TOOLS],
        write_scopes=list(WRITE_TOOLS),
    )


def _http_token_problems() -> list[str]:
    problems: list[str] = []
    read = os.environ.get("VCF_READ_TOKEN", "")
    admin = os.environ.get("VCF_ADMIN_TOKEN", "")
    if not read and not admin and not oauth_bearer.enabled():
        problems.append(
            "No bearer configured. Set VCF_READ_TOKEN / VCF_ADMIN_TOKEN and/or "
            "VCF_MCP_OAUTH_ISSUER. HTTP mode would otherwise expose live VCF "
            "admin APIs unauthenticated. Refusing to start."
        )
    if read and admin and secrets.compare_digest(read, admin):
        problems.append("VCF_READ_TOKEN and VCF_ADMIN_TOKEN are identical.")
    for name, tok in (("VCF_READ_TOKEN", read), ("VCF_ADMIN_TOKEN", admin)):
        if tok and len(tok) < 16:
            problems.append(f"{name} is shorter than 16 characters.")
    return problems


def _allowed_hosts() -> list[str]:
    """Hosts this server answers for (DNS-rebinding protection).

    ``VCF_ALLOWED_HOSTS`` wins. Otherwise the host of ``VCF_MCP_RESOURCE_URL``
    plus loopback.
    """
    raw = (os.environ.get("VCF_ALLOWED_HOSTS") or "").strip()
    if raw:
        return [h.strip() for h in raw.split(",") if h.strip()]
    hosts = ["localhost", "127.0.0.1"]
    own = urlsplit(_default_resource_url()).netloc
    if own and own not in hosts:
        hosts.insert(0, own)
    port = os.environ.get("PORT")
    if port:
        hosts.extend([f"localhost:{port}", f"127.0.0.1:{port}"])
    return hosts


def build_http_app():
    """ASGI app: Streamable HTTP MCP + bearer gate + /health + RFC 9728 metadata."""
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.responses import JSONResponse
    from starlette.types import ASGIApp, Receive, Scope, Send

    problems = _http_token_problems()
    if problems:
        raise SystemExit("Refusing to start HTTP mode:\n  - " + "\n  - ".join(problems))

    # Warm the index so /health reports a real count and the first call is fast.
    from . import specs

    op_count = len(specs.index())
    resource = _default_resource_url()
    metadata_url = resource.rsplit("/mcp", 1)[0] + oauth_bearer.OPR_PATHS[0]

    class AuthMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            path = scope.get("path", "")
            if path in ("/health", "/healthz"):
                await JSONResponse(
                    {"status": "ok", "operations": op_count, "server": "vcf-mcp"}
                )(scope, receive, send)
                return

            if oauth_bearer.is_opr_path(path):
                await JSONResponse(
                    oauth_bearer.protected_resource(
                        default_resource=resource,
                        scopes=["tools", *READ_TOOLS, *WRITE_TOOLS],
                        name="vcf-mcp",
                    )
                )(scope, receive, send)
                return

            presented = None
            for k, v in scope.get("headers") or []:
                if k == b"authorization":
                    raw = v.decode()
                    presented = raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()
                    break

            capability = _classify_token(presented)
            if capability is None:
                headers = {
                    "WWW-Authenticate": oauth_bearer.www_authenticate(
                        metadata_url=metadata_url, resource=resource
                    )
                }
                await JSONResponse(
                    {
                        "error": "unauthorized",
                        "detail": (
                            "Present a bearer token: VCF_READ_TOKEN for reads, "
                            "VCF_ADMIN_TOKEN for mutations, or an access token "
                            "from the configured OAuth issuer for this resource."
                        ),
                    },
                    status_code=401,
                    headers=headers,
                )(scope, receive, send)
                return

            token = CAPABILITY.set(capability)
            try:
                await self.app(scope, receive, send)
            finally:
                CAPABILITY.reset(token)

    hosts = _allowed_hosts()
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=[f"https://{h}" for h in hosts] + [f"http://{h}" for h in hosts],
    )
    return AuthMiddleware(mcp.streamable_http_app(transport_security=security))


def main_http() -> None:
    """Serve Streamable HTTP on $PORT (default 8080)."""
    import uvicorn

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(build_http_app(), host=host, port=port, log_level="info")


def main() -> None:
    # httpx logs a line per request at INFO. Against VCF that is one line per
    # inventory section and one per poll, all of it noise in the client's log.
    # Warnings and errors still come through.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # A PaaS sets $PORT; desktop clients launch with neither and get stdio.
    if os.environ.get("PORT") or os.environ.get("VCF_MCP_HTTP", "").lower() in ("1", "true", "yes"):
        main_http()
        return
    mcp.run()
