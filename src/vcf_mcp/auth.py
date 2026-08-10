"""Per-target authentication strategies with in-memory token caching.

Four schemes, each verified against the live estate before being written here:

    vcf_token       SDDC Manager / Installer -- POST /v1/tokens -> accessToken,
                    sent as `Authorization: Bearer`. Also returns a refreshToken.
    vcenter_session vCenter -- POST /api/session with HTTP Basic returns an
                    opaque session id, sent as `vmware-api-session-id`.
    nsx_basic       NSX -- HTTP Basic directly on every call. No session needed.
    ops_token       VCF Operations -- POST /suite-api/api/auth/token/acquire
                    returns {token, validity}, sent as `vRealizeOpsToken`.

Tokens live in memory for the life of the server process and are never written
to disk. A 401/403 from a call invalidates the cached token so the next attempt
re-authenticates rather than failing twice.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass

from . import config
from .config import Target

# SDDC Manager tokens are JWTs valid ~60 min; refresh a little early.
_DEFAULT_TTL = 45 * 60
_VCENTER_TTL = 25 * 60  # vCenter sessions idle out at 30 min


@dataclass
class Credential:
    headers: dict[str, str]
    expires_at: float
    source_key: str
    username: str


class AuthError(RuntimeError):
    pass


_cache: dict[str, Credential] = {}
_lock = threading.Lock()


def headers_for(target: Target, path: str, transport) -> dict[str, str]:
    """Auth headers for a call, minting or reusing a token as needed.

    `transport` is the raw request callable from client.py, passed in to avoid
    a circular import: auth needs to make HTTP calls, and client needs auth.
    """
    if any(path.startswith(p) for p in target.unauthenticated):
        return {}

    with _lock:
        cached = _cache.get(target.name)
        if cached and cached.expires_at > time.time():
            return dict(cached.headers)

    credential = _mint(target, transport)
    with _lock:
        _cache[target.name] = credential
    return dict(credential.headers)


def invalidate(target_name: str) -> None:
    with _lock:
        _cache.pop(target_name, None)


def cached_principal(target_name: str) -> dict | None:
    """What is currently authenticated, for diagnostics. Never the secret."""
    with _lock:
        cached = _cache.get(target_name)
    if not cached:
        return None
    return {
        "username": cached.username,
        "credential_source": cached.source_key,
        "expires_in_seconds": max(0, int(cached.expires_at - time.time())),
    }


def _mint(target: Target, transport) -> Credential:
    minter = {
        "vcf_token": _mint_vcf_token,
        "vcenter_session": _mint_vcenter_session,
        "nsx_basic": _mint_nsx_basic,
        "ops_token": _mint_ops_token,
        "avi_session": _mint_avi_session,
    }.get(target.auth)
    if minter is None:
        raise AuthError(f"target '{target.name}' has unknown auth scheme '{target.auth}'")

    candidates = config.credentials(target)
    if not candidates and target.credential_via:
        candidates = [_fetch_from_credential_store(target, transport)]

    failures = []
    for username, password, source in candidates:
        try:
            return minter(target, username, password, source, transport)
        except AuthError as exc:
            failures.append(str(exc))
    raise AuthError(
        f"could not authenticate to {target.product} ({target.host}) after "
        f"{len(failures)} attempt(s): " + " | ".join(failures)
    )


def _fetch_from_credential_store(target: Target, transport) -> tuple[str, str, str]:
    """Fetch a VCF-generated credential from another appliance's store.

    Avi's admin password is generated at deploy time and held only by SDDC
    Manager (GET /v1/credentials, resourceType NSX_ALB). The value stays in
    memory: it is used to log in and never returned, logged, or cached to
    disk.
    """
    store_name, resource_type = target.credential_via
    store = config.get_target(store_name)

    status, listing, _ = transport(
        store, "GET", "/v1/credentials", query={"resourceType": resource_type}
    )
    if status != 200 or not isinstance(listing, dict):
        raise AuthError(
            f"could not list {resource_type} credentials on '{store_name}': HTTP {status}"
        )
    elements = [
        e
        for e in (listing.get("elements") or [])
        if isinstance(e, dict) and e.get("credentialType") == "API"
    ] or (listing.get("elements") or [])
    if not elements:
        raise AuthError(
            f"no {resource_type} credential exists in '{store_name}' -- is the "
            f"{target.product} actually VCF-managed? Set VCF_MCP_"
            f"{target.name.upper()}_PASSWORD to provide one directly."
        )

    status, detail, _ = transport(store, "GET", f"/v1/credentials/{elements[0]['id']}")
    if status != 200 or not isinstance(detail, dict) or not detail.get("password"):
        raise AuthError(
            f"credential {elements[0]['id']} on '{store_name}' returned no password "
            f"(HTTP {status})"
        )
    return (
        detail.get("username") or target.default_user,
        detail["password"],
        f"{store_name}:/v1/credentials ({resource_type})",
    )


def _basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _mint_vcf_token(target, username, password, source, transport) -> Credential:
    """SDDC Manager / Installer: POST /v1/tokens -> accessToken."""
    status, body, _ = transport(
        target,
        "POST",
        "/v1/tokens",
        body={"username": username, "password": password},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        authenticate=False,
    )
    if status in (200, 201) and isinstance(body, dict):
        token = body.get("accessToken") or body.get("access_token")
        if token:
            return Credential(
                headers={"Authorization": f"Bearer {token}"},
                expires_at=time.time() + _DEFAULT_TTL,
                source_key=source,
                username=username,
            )
    raise AuthError(f"{username} via {source}: HTTP {status} {_brief(body)}")


def _mint_vcenter_session(target, username, password, source, transport) -> Credential:
    """vCenter returns a bare quoted session id string from POST /api/session."""
    status, body, _ = transport(
        target,
        "POST",
        "/api/session",
        headers={
            "Authorization": _basic(username, password),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        authenticate=False,
    )
    if status not in (200, 201):
        raise AuthError(f"{username} via {source}: HTTP {status} {_brief(body)}")
    session = body
    if isinstance(session, dict):  # some builds wrap it
        session = session.get("value") or session.get("session_id")
    if isinstance(session, str):
        session = session.strip().strip('"')
    if not session:
        raise AuthError(f"vCenter returned no session id: {_brief(body)}")
    return Credential(
        headers={"vmware-api-session-id": session},
        expires_at=time.time() + _VCENTER_TTL,
        source_key=source,
        username=username,
    )


def _mint_nsx_basic(target, username, password, source, transport) -> Credential:
    """NSX accepts Basic on every request; no round trip needed to mint."""
    return Credential(
        headers={"Authorization": _basic(username, password)},
        expires_at=time.time() + _DEFAULT_TTL,
        source_key=source,
        username=username,
    )


def _mint_ops_token(target, username, password, source, transport) -> Credential:
    """VCF Operations token acquire. `validity` is an epoch in milliseconds."""
    status, body, _ = transport(
        target,
        "POST",
        "/suite-api/api/auth/token/acquire",
        body={"username": username, "password": password},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        authenticate=False,
    )
    if status != 200 or not isinstance(body, dict) or not body.get("token"):
        raise AuthError(f"{username} via {source}: HTTP {status} {_brief(body)}")

    expires = time.time() + _DEFAULT_TTL
    validity = body.get("validity")
    if isinstance(validity, (int, float)) and validity > 0:
        # Refresh a minute before the appliance says it lapses.
        expires = min(expires, validity / 1000.0 - 60)
    return Credential(
        headers={"Authorization": f"vRealizeOpsToken {body['token']}"},
        expires_at=expires,
        source_key=source,
        username=username,
    )


def _mint_avi_session(target, username, password, source, transport) -> Credential:
    """Avi controller session login.

    Basic auth is rejected outright (401). POST /login sets a family of
    cookies -- sessionid, csrftoken, avi-sessionid -- which the shared HTTP
    client's cookie jar holds and replays automatically for this host. What
    must be added per request is the CSRF triple: X-CSRFToken echoing the
    csrftoken cookie, and a same-origin Referer, or every write is refused.
    """
    from . import client as _client_mod  # late import; client imports auth

    status, body, _ = transport(
        target,
        "POST",
        "/login",
        body={"username": username, "password": password},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        authenticate=False,
    )
    if status not in (200, 201):
        raise AuthError(f"{username} via {source}: HTTP {status} {_brief(body)}")

    csrf = _client_mod.cookie_value(target.host, "csrftoken")
    if not csrf:
        raise AuthError(
            f"Avi login succeeded but no csrftoken cookie landed in the jar -- "
            f"cannot build CSRF headers for {target.host}"
        )
    headers = {"X-CSRFToken": csrf, "Referer": f"https://{target.host}/"}
    # Pin the API dialect when the controller states its version; without the
    # header Avi assumes the controller's own version, which is also correct.
    if isinstance(body, dict):
        version = ((body.get("version") or {}).get("Version")) if isinstance(body.get("version"), dict) else None
        if version:
            headers["X-Avi-Version"] = version
    return Credential(
        headers=headers,
        expires_at=time.time() + _VCENTER_TTL,  # same idle-timeout ballpark
        source_key=source,
        username=username,
    )


def _brief(body) -> str:
    if isinstance(body, dict):
        for key in ("message", "error_message", "detail", "errorCode"):
            if body.get(key):
                return str(body[key])[:200]
        return json.dumps(body)[:200]
    return str(body)[:200]
