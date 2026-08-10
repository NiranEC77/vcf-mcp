"""Tool implementations.

Eight tools, deliberately few: a registry of what can be talked to, a way to
find an operation, a way to read its signature, a way to dry-run a spec, a
way to call it, a way to follow the long-running task most writes return, a
curated estate snapshot, and the audit trail.

That set covers all 7,698 indexed operations at a fixed context cost, which
is the whole point -- one MCP tool per endpoint would not fit in a context
window, let alone leave room for the work.
"""
from __future__ import annotations

import json
import time
from typing import Any

from . import auth, client, config, specs

DEFAULT_MAX_CHARS = 20_000

# Where each product reports the progress of an asynchronous operation.
_TASK_PATHS = {
    "sddc": "/v1/tasks/{id}",
    "installer": "/v1/tasks/{id}",
}
# Compared case-insensitively -- these products disagree on capitalisation.
_SUCCEEDED = {"SUCCESSFUL", "SUCCEEDED", "COMPLETED", "SUCCESS"}
_FAILED = {"FAILED", "COMPLETED_WITH_FAILURE", "CANCELLED", "ERROR"}
_TERMINAL = _SUCCEEDED | _FAILED


def targets(check_reachability: bool = True) -> dict:
    """Every configured appliance, what it serves, and whether it answers."""
    spec_counts: dict[str, int] = {}
    for entry in specs.index():
        for name in entry["targets"]:
            spec_counts[name] = spec_counts.get(name, 0) + 1

    rows = []
    for name, target in config.TARGETS.items():
        row: dict[str, Any] = {
            "target": name,
            "product": target.product,
            "host": target.host or f"(unset: {config.host_env_var(name)})",
            "auth": target.auth,
            "operations": spec_counts.get(name, 0),
            # Avi vendors one spec per object type (170 files); the list is
            # noise at that size, the count is the information.
            "specs": list(target.specs)
            if len(target.specs) <= 8
            else f"{len(target.specs)} spec files",
            "notes": target.notes,
        }
        if check_reachability:
            row.update(client.reachable(target))
        principal = auth.cached_principal(name)
        if principal:
            row["authenticated_as"] = principal
        rows.append(row)

    return {
        "targets": sorted(rows, key=lambda r: -r["operations"]),
        "total_operations": len(specs.index()),
        "credentials_from": str(config.env_file()),
        "tls_verification": config.verify_tls(),
        "audit_log": str(config.AUDIT_LOG),
        "hint": "Use vcf_search_api to find an operation, vcf_describe_api for its "
        "signature, then vcf_call to run it.",
    }


def search_api(
    query: str,
    target: str | None = None,
    method: str | None = None,
    limit: int = 25,
    include_deprecated: bool = False,
) -> dict:
    if target:
        config.get_target(target)  # raises with the known names if wrong
    found = specs.search(query, target, method, limit, include_deprecated)
    out = {
        "query": query,
        "target": target,
        "count": len(found["results"]),
        "results": found["results"],
    }
    if found["hidden_deprecated"]:
        out["hidden_deprecated"] = found["hidden_deprecated"]
        out["hint"] = (
            "These matched your query but are deprecated in this VCF release -- "
            "prefer the ranked results above. Pass include_deprecated=true to "
            "search them anyway."
        )
    return out


def describe_api(
    target: str | None = None,
    operation_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
    depth: int = 3,
    max_properties: int = 60,
) -> dict:
    if target:
        config.get_target(target)
    entry = specs.find(target=target, operation_id=operation_id, method=method, path=path)
    described = specs.describe(entry, depth=max(1, min(depth, 6)), max_properties=max_properties)
    described["example_call"] = {
        "tool": "vcf_call",
        "target": described["target"],
        "method": described["method"],
        "path": described["path"],
    }
    return described


def call(
    target: str,
    method: str,
    path: str,
    query: dict | None = None,
    body: Any = None,
    timeout: float | None = None,
    max_response_chars: int = DEFAULT_MAX_CHARS,
) -> dict:
    """Execute one operation against a target.

    Unknown paths are rejected before reaching the wire only when they cannot
    be matched to the spec at all *and* look like a typo; otherwise the call
    goes through, because the specs do not always cover every path a given
    build serves.
    """
    resolved = config.get_target(target)
    method = (method or "GET").upper()
    if not path.startswith("/"):
        path = "/" + path

    known = None
    try:
        known = specs.find(target=target, method=method, path=path.split("?")[0])
    except LookupError:
        pass

    status, payload, headers = client.request(
        resolved, method, path, query=query, body=body, timeout=timeout
    )

    result: dict[str, Any] = {
        "target": target,
        "method": method,
        "path": path,
        "status": status,
        "ok": 200 <= status < 300,
    }
    if known:
        result["operationId"] = known["op"]
    else:
        result["note"] = (
            "This method+path is not in the vendored spec. It was sent anyway -- "
            "the appliance is the authority. Check vcf_search_api if the result "
            "looks wrong."
        )

    if isinstance(payload, dict) and not result["ok"]:
        # VCF error objects carry a remediationMessage that is genuinely useful.
        result["error"] = {
            key: payload[key]
            for key in ("errorCode", "message", "remediationMessage", "referenceToken", "arguments")
            if key in payload
        } or payload

    result["body"], truncated = _fit(payload, max_response_chars)
    if truncated:
        result["truncated"] = True
        result["truncation_hint"] = (
            "Response was shortened to fit. Narrow it with query parameters "
            "(most VCF list endpoints support pageSize/pageNumber or filters), "
            "or raise max_response_chars."
        )

    task_id = _task_id(status, payload, headers)
    if task_id and target in _TASK_PATHS:
        result["task_id"] = task_id
        result["task_hint"] = f"Follow with vcf_task(target='{target}', task_id='{task_id}')"
    return result


def task(target: str, task_id: str, wait_seconds: int = 0, poll_interval: float = 5.0) -> dict:
    """Read a long-running task, optionally waiting for it to finish.

    Most VCF mutations return 202 with a task id; the interesting information
    (which subtask failed, and why) only appears here.
    """
    resolved = config.get_target(target)
    template = _TASK_PATHS.get(target)
    if not template:
        raise ValueError(
            f"target '{target}' does not expose the /v1/tasks endpoint. "
            f"Task-style polling is available on: {', '.join(sorted(_TASK_PATHS))}."
        )
    path = template.format(id=task_id)

    deadline = time.time() + max(0, wait_seconds)
    polls = 0
    while True:
        status, payload, _ = client.request(resolved, "GET", path)
        polls += 1
        state = payload.get("status") if isinstance(payload, dict) else None
        # SDDC Manager reports "Successful", the docs say "SUCCESSFUL", and
        # other products shout. Compare case-insensitively or a finished task
        # is polled until the deadline and then reported as still running.
        done = isinstance(state, str) and state.upper() in _TERMINAL
        if done or status >= 400 or time.time() >= deadline:
            break
        time.sleep(min(poll_interval, max(0.5, deadline - time.time())))

    body, _ = _fit(payload, DEFAULT_MAX_CHARS)
    result = {
        "target": target,
        "task_id": task_id,
        "http_status": status,
        "status": state,
        "finished": bool(isinstance(state, str) and state.upper() in _TERMINAL),
        "succeeded": bool(isinstance(state, str) and state.upper() in _SUCCEEDED),
        "polls": polls,
        "task": body,
    }
    if isinstance(payload, dict):
        failures = [
            {"name": sub.get("name"), "status": sub.get("status"), "errors": sub.get("errors")}
            for sub in (payload.get("subTasks") or [])
            if isinstance(sub, dict)
            and isinstance(sub.get("status"), str)
            and sub["status"].upper() in _FAILED
        ]
        if failures:
            result["failed_subtasks"] = failures
    return result


# What a "what have I got?" question actually needs, per target. Each entry is
# (label, method, path, extractor) and any failure is reported, never raised.
_INVENTORY = {
    "sddc": [
        ("sddc_manager", "GET", "/v1/sddc-managers", None),
        ("domains", "GET", "/v1/domains", ("name", "type", "status", "id")),
        ("clusters", "GET", "/v1/clusters", ("name", "primaryDatastoreType", "isDefault", "id")),
        ("hosts", "GET", "/v1/hosts", ("fqdn", "status", "esxiVersion", "id")),
        ("vcenters", "GET", "/v1/vcenters", ("fqdn", "version", "id")),
        ("nsx_clusters", "GET", "/v1/nsxt-clusters", ("vipFqdn", "version", "id")),
        ("network_pools", "GET", "/v1/network-pools", ("name", "id")),
        ("vcf_services", "GET", "/v1/vcf-services", ("name", "version", "status")),
    ],
    "vcenter": [
        ("esxi_hosts", "GET", "/api/vcenter/host", ("name", "connection_state", "power_state")),
        ("datastores", "GET", "/api/vcenter/datastore", ("name", "type", "free_space", "capacity")),
    ],
    "nsx": [
        ("tier0_gateways", "GET", "/policy/api/v1/infra/tier-0s", ("display_name", "id")),
        ("tier1_gateways", "GET", "/policy/api/v1/infra/tier-1s", ("display_name", "id")),
        ("segments", "GET", "/policy/api/v1/infra/segments", ("display_name", "id")),
    ],
    "ops": [
        ("active_alerts", "GET", "/suite-api/api/alerts", ("alertLevel", "status", "alertId")),
    ],
    "avi": [
        ("clouds", "GET", "/api/cloud", ("name", "vtype", "uuid")),
        ("virtual_services", "GET", "/api/virtualservice", ("name", "enabled", "uuid")),
        ("pools", "GET", "/api/pool", ("name", "uuid")),
        ("service_engines", "GET", "/api/serviceengine", ("name", "uuid")),
    ],
}


def inventory(targets_wanted: list[str] | None = None, per_section_limit: int = 25) -> dict:
    """One cross-appliance snapshot of the estate.

    This is the question every session opens with, and answering it from
    search+describe+call would cost a dozen round trips.
    """
    wanted = targets_wanted or list(_INVENTORY)
    out: dict[str, Any] = {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    for name in wanted:
        if name not in _INVENTORY:
            out[name] = {"error": f"no inventory recipe for target '{name}'"}
            continue
        target = config.TARGETS[name]
        section: dict[str, Any] = {}
        for label, method, path, fields in _INVENTORY[name]:
            try:
                query = {"pageSize": 200} if name == "ops" else None
                status, payload, _ = client.request(target, method, path, query=query, timeout=60)
                if status >= 400:
                    section[label] = {"error": f"HTTP {status}", "detail": client.redact(payload)}
                    continue
                section[label] = _summarise(payload, fields, per_section_limit)
            except Exception as exc:  # a dead appliance must not kill the report
                section[label] = {"error": f"{type(exc).__name__}: {exc}"}
        out[name] = section
    return out


def _summarise(payload: Any, fields: tuple[str, ...] | None, limit: int) -> Any:
    """Reduce a list response to counts plus the fields that matter."""
    items = payload
    if isinstance(payload, dict):
        for key in ("elements", "value", "results", "alerts", "items"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
    if not isinstance(items, list):
        return client.redact(payload)

    rendered = []
    for item in items[:limit]:
        if isinstance(item, dict) and fields:
            row = {f: item[f] for f in fields if f in item}
            rendered.append(row or client.redact(item))
        else:
            rendered.append(client.redact(item))
    result: dict[str, Any] = {"count": len(items), "items": rendered}
    if len(items) > limit:
        result["note"] = f"showing {limit} of {len(items)}"
    return result


def validate(
    target: str,
    path: str,
    body: Any = None,
    wait_seconds: int = 120,
    poll_interval: float = 5.0,
) -> dict:
    """Dry-run a spec against its /validations endpoint without executing it.

    SDDC Manager and the Installer pair most mutating endpoints with a
    validation twin: POST /v1/clusters -> POST /v1/clusters/validations takes
    the *same* body, checks it end to end, and changes nothing. This tool
    accepts either the real path or the validation path, resolves the twin,
    runs it, and polls until the validation completes.

    For targets without that convention (vCenter uses ?action=check...
    operations instead), it reports the nearest check-style operations rather
    than guessing.
    """
    resolved = config.get_target(target)
    if not path.startswith("/"):
        path = "/" + path
    base = path.split("?")[0].rstrip("/")

    # Accept the validation path itself, or derive it from the real one.
    # The twin must match EXACTLY: template matching would happily bind
    # ".../supervisors/validations" to ".../supervisors/{supervisor}" and
    # POST a validation body at a real resource named "validations".
    candidate = base if base.endswith("/validations") else base + "/validations"
    entry = next(
        (
            e
            for e in specs.index()
            if target in e["targets"] and e["method"] == "POST" and e["path"] == candidate
        ),
        None,
    )
    if entry is None:
        alternatives = [
            {"method": e["method"], "path": e["path"], "operationId": e["op"]}
            for e in specs.index()
            if target in e["targets"]
            and e["method"] == "POST"
            and (e["path"].rstrip("/").endswith("/validations") or "action=check" in e["path"])
        ]
        near = [a for a in alternatives if base.split("/")[-1].rstrip("s") in a["path"]]
        return {
            "target": target,
            "path": path,
            "validated": False,
            "error": f"no validation endpoint found for POST {candidate}",
            "hint": (
                "This resource has no /validations twin. Check-style operations "
                "available on this target are listed under 'alternatives' -- they "
                "can be run directly with vcf_call, they do not change state."
            ),
            "alternatives": (near or alternatives)[:12],
        }

    status, payload, _ = client.request(
        resolved, "POST", entry["path"], body=body, timeout=120
    )
    result: dict[str, Any] = {
        "target": target,
        "validation_endpoint": entry["path"],
        "operationId": entry["op"],
        "http_status": status,
    }
    if status >= 400:
        # For simple specs the appliance rejects at POST time -- that 400 IS
        # the verdict, and its message names the failing item outright.
        result["validated"] = False
        if isinstance(payload, dict):
            result["error"] = {
                key: payload[key]
                for key in ("errorCode", "message", "remediationMessage", "referenceToken")
                if key in payload
            } or client.redact(payload)
        else:
            result["error"] = payload
        return result

    # Poll the validation to completion when it reports an id and a matching
    # GET .../validations/{id} exists.
    validation_id = payload.get("id") if isinstance(payload, dict) else None
    execution = payload.get("executionStatus") if isinstance(payload, dict) else None
    if validation_id and execution and execution.upper() not in ("COMPLETED", "FAILED"):
        poll_path = f"{entry['path']}/{validation_id}"
        deadline = time.time() + max(0, wait_seconds)
        while time.time() < deadline:
            time.sleep(poll_interval)
            status, payload, _ = client.request(resolved, "GET", poll_path)
            execution = payload.get("executionStatus") if isinstance(payload, dict) else None
            if status >= 400 or (execution and execution.upper() in ("COMPLETED", "FAILED")):
                break

    if isinstance(payload, dict):
        outcome = str(payload.get("resultStatus") or "").upper()
        result["execution_status"] = payload.get("executionStatus")
        result["result_status"] = payload.get("resultStatus")
        result["validated"] = outcome == "SUCCEEDED"
        failures = [
            {
                "description": check.get("description"),
                "result": check.get("resultStatus"),
                "error": client.redact(check.get("errorResponse")),
            }
            for check in (payload.get("validationChecks") or [])
            if isinstance(check, dict)
            and str(check.get("resultStatus", "")).upper() not in ("SUCCEEDED", "")
        ]
        if failures:
            result["failed_checks"] = failures
        else:
            body_fitted, _ = _fit(payload, 8_000)
            result["detail"] = body_fitted
    else:
        result["validated"] = None
        result["detail"] = payload
    return result


def audit(limit: int = 50) -> dict:
    """Recent mutating calls made through this server."""
    path = config.AUDIT_LOG
    if not path.exists():
        return {"audit_log": str(path), "entries": [], "note": "no mutations recorded yet"}
    lines = path.read_text().splitlines()[-max(1, limit) :]
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return {"audit_log": str(path), "count": len(entries), "entries": entries}


def _task_id(status: int, payload: Any, headers: dict[str, str]) -> str | None:
    """Pull the task id out of an accepted-but-not-finished response.

    Deliberately conservative. Almost every VCF object has an `id`, so
    treating any `id` as a task id would tell the caller to poll
    /v1/tasks/<a-host-id> and get a confusing 404. Only an explicit 202, a
    Location header pointing at /tasks/, or a body that is recognisably a
    task counts.
    """
    location = headers.get("location") or headers.get("Location") or ""
    if "/tasks/" in location:
        candidate = location.rstrip("/").rsplit("/", 1)[-1]
        if candidate:
            return candidate

    if not isinstance(payload, dict):
        return None
    for key in ("taskId", "task_id"):
        if isinstance(payload.get(key), str):
            return payload[key]

    looks_like_task = "subTasks" in payload or (
        isinstance(payload.get("status"), str)
        and payload["status"].upper() in _TERMINAL | {"IN_PROGRESS", "PENDING", "IN PROGRESS"}
    )
    if (status == 202 or looks_like_task) and isinstance(payload.get("id"), str):
        return payload["id"]
    return None


def _fit(payload: Any, max_chars: int) -> tuple[Any, bool]:
    """Keep a response inside a sane size, shrinking lists before dropping data.

    The six products in this estate each name their collection differently --
    `elements`, `value`, `results`, `resourceList`, `alerts` -- so rather than
    keep a list of key names in step with them, find the longest list in the
    response and shrink that. Dropping whole items with a count is far more
    useful to a caller than slicing the JSON text mid-token.
    """
    if payload is None:
        return None, False
    if len(json.dumps(payload, default=str)) <= max_chars:
        return payload, False

    if isinstance(payload, dict):
        lists = [(k, v) for k, v in payload.items() if isinstance(v, list) and v]
        if lists:
            key, items = max(lists, key=lambda pair: len(pair[1]))
            kept = list(items)
            while len(kept) > 1 and (
                len(json.dumps({**payload, key: kept}, default=str)) > max_chars
            ):
                kept = kept[: len(kept) // 2]
            shrunk = {**payload, key: kept}
            if len(kept) < len(items):
                shrunk["_truncated"] = f"showing {len(kept)} of {len(items)} in '{key}'"
            if len(json.dumps(shrunk, default=str)) > max_chars:
                shrunk["_truncated"] = (
                    f"'{key}' has {len(items)} items and even one exceeds "
                    f"max_response_chars={max_chars}; showing it trimmed"
                )
                shrunk[key] = [_clip(kept[0], max_chars)]
            return shrunk, True

    if isinstance(payload, list):
        kept = list(payload)
        while len(kept) > 1 and len(json.dumps(kept, default=str)) > max_chars:
            kept = kept[: len(kept) // 2]
        return {
            "_truncated": f"showing {len(kept)} of {len(payload)} items",
            "items": [_clip(item, max_chars) for item in kept],
        }, True

    return _clip(payload, max_chars), True


def _clip(value: Any, max_chars: int) -> Any:
    """Last resort: shorten a single oversized value without corrupting JSON."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if len(text) <= max_chars:
        return value
    return text[: max(0, max_chars - 20)] + "...<clipped>"
