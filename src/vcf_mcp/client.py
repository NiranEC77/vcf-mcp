"""HTTP transport for every target: TLS policy, auth retry, audit trail.

One function does the work -- `request()` -- and everything else in the server
goes through it, so there is exactly one place where a call to the estate can
happen, one place TLS is decided, and one place mutations get recorded.

TLS verification is off by default: these appliances present self-signed certs
on an island network with no CA, which is the same posture the estate's own
scripts take. Set VCF_MCP_VERIFY_TLS=1 to enforce it.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx

from . import auth, config
from .config import Target

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_REDACT = ("password", "secret", "token", "credential", "passphrase", "privatekey", "private_key")

_clients: dict[bool, httpx.Client] = {}
_client_lock = threading.Lock()
_audit_lock = threading.Lock()


def _client(verify: bool) -> httpx.Client:
    """One pooled client per TLS policy, reused across calls."""
    with _client_lock:
        existing = _clients.get(verify)
        if existing is None:
            existing = httpx.Client(
                verify=verify,
                timeout=httpx.Timeout(30.0, connect=10.0, read=300.0),
                follow_redirects=False,
                headers={"User-Agent": "vcf-mcp/0.1"},
            )
            _clients[verify] = existing
        return existing


def request(
    target: Target,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    body: Any = None,
    headers: dict[str, str] | None = None,
    authenticate: bool = True,
    timeout: float | None = None,
) -> tuple[int, Any, dict[str, str]]:
    """Perform one call. Returns (status, parsed_body, response_headers).

    Transport-level failures raise; HTTP error statuses are returned normally
    so the caller can show the appliance's own error object, which for VCF is
    far more useful than an exception (it carries remediationMessage).
    """
    method = method.upper()
    if not path.startswith("/"):
        path = "/" + path

    host = config.require_host(target)
    sent = {"Accept": "application/json"}
    if body is not None:
        sent["Content-Type"] = "application/json"
    if authenticate:
        sent.update(auth.headers_for(target, path, request))
    if headers:
        sent.update(headers)

    url = f"https://{host}{path}"
    if query:
        url += ("&" if "?" in path else "?") + urlencode(
            {k: v for k, v in query.items() if v is not None}, doseq=True
        )

    started = time.time()
    status, parsed, response_headers = _send(url, method, sent, body, timeout)

    # A stale token looks like a 401/403. Mint a fresh one and try once more.
    if status in (401, 403) and authenticate:
        auth.invalidate(target.name)
        sent.update(auth.headers_for(target, path, request))
        status, parsed, response_headers = _send(url, method, sent, body, timeout)

    if method in MUTATING and authenticate:
        _audit(target, method, path, query, body, status, time.time() - started)
    return status, parsed, response_headers


def _send(url, method, headers, body, timeout):
    client = _client(config.verify_tls())
    kwargs: dict[str, Any] = {"headers": headers}
    if body is not None:
        kwargs["content"] = json.dumps(body).encode() if not isinstance(body, (bytes, str)) else body
    if timeout is not None:
        kwargs["timeout"] = httpx.Timeout(timeout, connect=10.0, read=timeout)

    response = client.request(method, url, **kwargs)
    text = response.text
    parsed: Any
    if not text.strip():
        parsed = None
    else:
        try:
            parsed = response.json()
        except ValueError:
            parsed = text
    return response.status_code, parsed, dict(response.headers)


def redact(value: Any, _depth: int = 0) -> Any:
    """Copy of a payload with anything secret-looking replaced.

    Used for the audit trail: a credential-rotation call must be recorded as
    having happened without the new password landing in a log file.
    """
    if _depth > 6:
        return "<deep>"
    if isinstance(value, dict):
        out = {}
        for key, inner in value.items():
            if any(marker in key.lower() for marker in _REDACT):
                out[key] = "<redacted>"
            else:
                out[key] = redact(inner, _depth + 1)
        return out
    if isinstance(value, list):
        return [redact(item, _depth + 1) for item in value[:20]]
    if isinstance(value, str) and len(value) > 300:
        return value[:300] + f"...<{len(value)} chars>"
    return value


def _audit(target, method, path, query, body, status, elapsed) -> None:
    """Append one JSONL line per mutating call. Best effort -- never fatal."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target.name,
        "host": target.host,
        "method": method,
        "path": path,
        "query": redact(query) if query else None,
        "body": redact(body) if body is not None else None,
        "status": status,
        "elapsed_ms": int(elapsed * 1000),
    }
    line = json.dumps(entry) + "\n"
    try:
        path = config.AUDIT_LOG
        # Hosted copies have an ephemeral disk; VCF_MCP_AUDIT_LOG=/dev/stdout
        # keeps mutations in the platform log. Do not mkdir("/dev").
        stream = {"/dev/stdout": sys.stdout, "-": sys.stdout, "stdout": sys.stdout,
                  "/dev/stderr": sys.stderr, "stderr": sys.stderr}.get(str(path))
        if stream is not None:
            with _audit_lock:
                stream.write(line)
                stream.flush()
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with _audit_lock:
            with path.open("a") as handle:
                handle.write(line)
    except OSError:
        pass


def cookie_value(host: str, name: str) -> str | None:
    """Read one cookie for a host from the pooled client's jar.

    Avi-style session auth stores its state as cookies set by /login; the jar
    replays them automatically, but the CSRF header has to echo the cookie
    value explicitly, so auth needs to read it back.
    """
    with _client_lock:
        clients = list(_clients.values())
    for pooled in clients:
        for cookie in pooled.cookies.jar:
            if cookie.name == name and cookie.domain.lstrip(".") == host:
                return cookie.value
    return None


def reachable(target: Target, timeout: float = 6.0) -> dict[str, Any]:
    """Cheap liveness probe that does not need credentials."""
    if not target.host:
        return {"reachable": False, "error": f"no address configured ({config.host_env_var(target.name)} unset)"}
    try:
        client = _client(config.verify_tls())
        response = client.request(
            "GET", f"https://{target.host}/", timeout=httpx.Timeout(timeout), headers={}
        )
        return {"reachable": True, "http_status": response.status_code}
    except Exception as exc:  # noqa: BLE001 - any transport failure means "no"
        return {"reachable": False, "error": f"{type(exc).__name__}: {exc}"}
