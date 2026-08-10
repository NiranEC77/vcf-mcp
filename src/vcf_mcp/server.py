"""MCP server exposing VMware Cloud Foundation to a Claude Code session.

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
        "Configure and manage a VMware Cloud Foundation 9.1 estate. Start with "
        "vcf_targets to see the appliances, or vcf_inventory for a snapshot of "
        "what exists. To do anything specific: vcf_search_api to find the "
        "operation, vcf_describe_api to read its schema, vcf_validate to dry-run a spec where a /validations twin exists, then vcf_call to run it. "
        "Writes take effect immediately on live infrastructure and some are "
        "irreversible, so describe before you call, and follow any returned "
        "task id with vcf_task rather than assuming success."
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


def main() -> None:
    # httpx logs a line per request at INFO. Against VCF that is one line per
    # inventory section and one per poll, all of it noise in the client's log.
    # Warnings and errors still come through.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    mcp.run()
