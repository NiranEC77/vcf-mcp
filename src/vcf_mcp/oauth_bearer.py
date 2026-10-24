"""OAuth 2.0 bearer tokens on the HTTP transport.

When vcf-mcp runs as a Streamable HTTP server it is an OAuth *resource
server*. Two kinds of bearer are accepted:

1. The static ``VCF_READ_TOKEN`` / ``VCF_ADMIN_TOKEN`` (see ``server.py``).
2. A JWT access token issued by the authorization server named in
   ``VCF_MCP_OAUTH_ISSUER``. The token must be signed by that issuer's
   JWKS, unexpired, and carry an ``aud`` that names this server (its own
   ``/mcp`` URL or one of ``VCF_MCP_OAUTH_AUDIENCES``).

What the token's ``scope`` may say:

* a **tool name** (``vcf_call``, ``vcf_list_vms`` ...) — that exact tool;
  a write tool may mutate, a read tool may not;
* ``urn:iam:agent:intent:<tool>`` — the same rule, one tool;
* the blanket ``tools`` scope — the read catalog, plus ``vcf_call``
  for GET only.

A generic job scope such as ``urn:iam:agent:intent:vcf-inspection``
authorizes nothing. It used to become admin. That mapping is gone.
Operators who still have a gateway job can set
``VCF_MCP_GATEWAY_JOB_MAP`` to a JSON object of scope to tool names.
The default map is empty. Invalid JSON authorizes nothing. Stdio
clients that launch this process themselves are unchanged.

This module also serves RFC 9728 Protected Resource Metadata at
``/.well-known/oauth-protected-resource`` so clients can discover the
issuer, and advertises it in ``WWW-Authenticate`` on 401.

Never log bearer values.
"""

from __future__ import annotations

import json
import os
import ssl
import threading
import time
import urllib.request
from typing import Any, Iterable

OPR_PATHS = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
)
DEFAULT_INTENT_PREFIX = "urn:iam:agent:intent:"

VCF_READ_SCOPES = (
    "vcf_targets",
    "vcf_search_api",
    "vcf_describe_api",
    "vcf_validate",
    "vcf_inventory",
    "vcf_audit",
    "vcf_list_vms",
    "vcf_get_vm",
    "vcf_vm_power_state",
    "vcf_list_networks",
    "vcf_list_segments",
    "vcf_list_gateways",
    "vcf_list_datastores",
    "vcf_get_datastore",
    "vcf_datastore_policy",
    "vcf_list_alerts",
    "vcf_ops_snapshot",
    "vcf_vm_disk_latency",
    "vcf_task",
)
VCF_WRITE_SCOPES = (
    "vcf_call",
    "vcf_start_vm",
    "vcf_stop_vm",
    "vcf_reset_vm",
    "vcf_suspend_vm",
)

_jwks_lock = threading.Lock()
_jwks_cache: tuple[float, dict[str, Any]] | None = None
_JWKS_TTL = 300.0


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def issuer() -> str:
    """Authorization server issuer, no trailing slash. Empty disables JWTs."""
    return (os.environ.get("VCF_MCP_OAUTH_ISSUER") or "").strip().rstrip("/")


def enabled() -> bool:
    return bool(issuer())


def jwks_uri() -> str:
    explicit = (os.environ.get("VCF_MCP_OAUTH_JWKS_URI") or "").strip()
    if explicit:
        return explicit
    return _discover_jwks_uri()


def resource_url(*, default: str = "") -> str:
    raw = (os.environ.get("VCF_MCP_RESOURCE_URL") or default).strip()
    return raw.rstrip("/")


def audiences(*, default_resource: str = "") -> list[str]:
    """Every ``aud`` value this server answers to.

    Behind an agent gateway the token is usually minted for the gateway's
    route, not for this server's own URL. List that route in
    ``VCF_MCP_OAUTH_AUDIENCES`` (comma separated).
    """
    out = [resource_url(default=default_resource)]
    extra = (os.environ.get("VCF_MCP_OAUTH_AUDIENCES") or "").strip()
    if extra:
        out.extend(p.strip() for p in extra.split(",") if p.strip())
    seen: set[str] = set()
    uniq: list[str] = []
    for item in out:
        item = item.rstrip("/")
        if item and item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def intent_prefix() -> str:
    return (os.environ.get("VCF_MCP_OAUTH_INTENT_PREFIX") or DEFAULT_INTENT_PREFIX).strip()


def required_scopes() -> list[str]:
    raw = (os.environ.get("VCF_MCP_OAUTH_REQUIRED_SCOPES") or "tools").strip()
    return [s for s in raw.split() if s]


# --------------------------------------------------------------------------
# metadata
# --------------------------------------------------------------------------


def protected_resource(*, default_resource: str, scopes: Iterable[str], name: str) -> dict[str, Any]:
    sc = list(scopes) if scopes else required_scopes()
    doc: dict[str, Any] = {
        "resource": resource_url(default=default_resource),
        "bearer_methods_supported": ["header"],
        "scopes_supported": sc,
        "resource_name": name,
    }
    if enabled():
        doc["authorization_servers"] = [issuer()]
    return doc


def www_authenticate(*, metadata_url: str, resource: str) -> str:
    return f'Bearer realm="mcp", resource_metadata="{metadata_url}", resource="{resource}"'


def is_opr_path(path: str) -> bool:
    p = (path or "").split("?", 1)[0]
    return p in OPR_PATHS


# --------------------------------------------------------------------------
# claims helpers (pure, unit-testable)
# --------------------------------------------------------------------------


def looks_like_jwt(token: str) -> bool:
    if token.count(".") != 2:
        return False
    header, payload, sig = token.split(".")
    return bool(header and payload and sig)


def _scope_set(claim: Any) -> set[str]:
    if isinstance(claim, str):
        return {p for p in claim.split() if p}
    if isinstance(claim, (list, tuple)):
        return {str(p) for p in claim if p}
    return set()


def scopes_of(claims: dict[str, Any] | None) -> set[str]:
    if not isinstance(claims, dict):
        return set()
    return _scope_set(claims.get("scope")) | _scope_set(claims.get("scp"))


def _aud_list(claim: Any) -> list[str]:
    if claim is None:
        return []
    if isinstance(claim, str):
        return [claim]
    if isinstance(claim, (list, tuple)):
        return [str(x) for x in claim if x]
    return []


def audience_ok(claims: dict[str, Any], allowed: Iterable[str]) -> bool:
    allowed_set = {a.rstrip("/") for a in allowed if a}
    for aud in _aud_list(claims.get("aud")):
        if aud.rstrip("/") in allowed_set:
            return True
    return False


def expand_read_scopes(needed: Iterable[str]) -> list[str]:
    """``tools`` means every read tool; named scopes are left alone."""
    reads = [s for s in needed if s]
    if "tools" not in reads:
        return reads
    return list(dict.fromkeys(reads + list(VCF_READ_SCOPES)))


def grant_ok(claims: dict[str, Any], needed: Iterable[str]) -> bool:
    need = {s for s in needed if s}
    if not need:
        return False
    return bool(scopes_of(claims) & need)


def mutating_grant(claims: dict[str, Any], write_scopes: Iterable[str]) -> bool:
    return bool(scopes_of(claims) & {s for s in write_scopes if s})


def intent_scopes(claims: dict[str, Any] | None) -> list[str]:
    """Gateway-issued job scopes on the token."""
    prefix = intent_prefix()
    return sorted(s for s in scopes_of(claims) if s.startswith(prefix))


def intent_grant(claims: dict[str, Any] | None) -> bool:
    """True when the token carries any scope with the intent prefix.

    This is a detector. It is not permission. A generic job name does
    not authorize a tool.
    """
    return bool(intent_scopes(claims))


def gateway_job_map() -> dict[str, tuple[str, ...]]:
    """Explicit job-to-tools map. Default is empty.

    ``VCF_MCP_GATEWAY_JOB_MAP`` is a JSON object whose keys are full
    scope strings and whose values are tool names. A generic intent
    that is not listed here authorizes nothing. Listing a write tool
    is an operator choice for that one tool, not a grant of every
    mutation. Invalid JSON fails closed.
    """
    raw = (os.environ.get("VCF_MCP_GATEWAY_JOB_MAP") or "").strip()
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(doc, dict):
        return {}
    mapped: dict[str, tuple[str, ...]] = {}
    for key, value in doc.items():
        if not isinstance(key, str) or not isinstance(value, list):
            continue
        tools = tuple(item for item in value if isinstance(item, str) and item)
        if tools:
            mapped[key] = tools
    return mapped


def tools_from_claims(
    claims: dict[str, Any],
    *,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> tuple[frozenset[str], frozenset[str]]:
    """Exact tools a verified token may invoke, and which of those may mutate.

    A scope authorizes a tool only when it is that tool's name or
    ``<intent-prefix><tool>``. ``tools`` authorizes the read catalog
    plus ``vcf_call`` as a read: GET may proceed, and the operation
    guard still refuses POST. A generic intent is ignored unless
    ``gateway_job_map`` lists it.
    """
    scopes = scopes_of(claims)
    read_names = set(expand_read_scopes(read_scopes))
    read_names.discard("tools")
    write_names = {scope for scope in write_scopes if scope}
    known = read_names | write_names
    prefix = intent_prefix()
    allowed: set[str] = set()
    writes: set[str] = set()

    def add(tool: str, *, as_write: bool) -> None:
        if tool not in known:
            return
        allowed.add(tool)
        if as_write and tool in write_names:
            writes.add(tool)

    if "tools" in scopes:
        allowed.update(read_names)
        if "vcf_call" in known:
            allowed.add("vcf_call")
    for scope in scopes:
        if scope == "tools":
            continue
        if scope in known:
            add(scope, as_write=True)
            continue
        if scope.startswith(prefix):
            add(scope[len(prefix) :], as_write=True)
    for scope in scopes:
        for tool in gateway_job_map().get(scope, ()):
            add(tool, as_write=True)
    return frozenset(allowed), frozenset(writes)


def capability_for(
    claims: dict[str, Any],
    *,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> str | None:
    """'admin' when a verified token names a write tool, else 'read' or None.

    Admin here means the token may mutate the write tools it names.
    It does not mean every mutation. A generic intent is not admin.
    """
    allowed, writes = tools_from_claims(
        claims, read_scopes=read_scopes, write_scopes=write_scopes
    )
    if writes:
        return "admin"
    if allowed:
        return "read"
    return None


# --------------------------------------------------------------------------
# verification (network)
# --------------------------------------------------------------------------


def _ssl_ctx() -> ssl.SSLContext:
    flag = (os.environ.get("VCF_MCP_OAUTH_TLS_VERIFY") or "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def _get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as resp:
        doc = json.loads(resp.read().decode())
    if not isinstance(doc, dict):
        raise ValueError("expected a JSON object")
    return doc


def _discover_jwks_uri() -> str:
    """RFC 8414 / OpenID discovery from the issuer."""
    base = issuer()
    if not base:
        return ""
    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        try:
            doc = _get_json(base + path)
        except Exception:
            continue
        uri = doc.get("jwks_uri")
        if isinstance(uri, str) and uri:
            return uri
    return ""


def _load_jwks() -> dict[str, Any]:
    global _jwks_cache
    now = time.time()
    with _jwks_lock:
        if _jwks_cache and _jwks_cache[0] > now:
            return _jwks_cache[1]
    uri = jwks_uri()
    if not uri:
        raise ValueError("no jwks_uri: set VCF_MCP_OAUTH_JWKS_URI or make the issuer discoverable")
    doc = _get_json(uri)
    if not isinstance(doc.get("keys"), list):
        raise ValueError("jwks document missing keys")
    with _jwks_lock:
        _jwks_cache = (now + _JWKS_TTL, doc)
    return doc


def verify_jwt(token: str) -> dict[str, Any] | None:
    """Return claims for a live token from the configured issuer, else None.

    Does not decide capability; see ``capability_for`` / ``classify``.
    """
    if not enabled():
        return None
    try:
        import jwt  # PyJWT[crypto]
        from jwt import PyJWK
    except ImportError:
        return None
    if not looks_like_jwt(token):
        return None
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    kid = header.get("kid")
    try:
        jwks = _load_jwks()
    except Exception:
        return None
    key = None
    for item in jwks.get("keys") or []:
        if not isinstance(item, dict):
            continue
        if kid and item.get("kid") != kid:
            continue
        try:
            key = PyJWK.from_dict(item).key
            break
        except Exception:
            continue
    if key is None:
        return None
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256", "ES256"],
            options={
                "verify_aud": False,  # multi-valued aud matched by audience_ok
                "verify_iss": False,  # matched below without trailing-slash pain
                "require": ["exp", "iss"],
            },
        )
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    if str(claims.get("iss") or "").rstrip("/") != issuer():
        return None
    return claims


def authorize_token(
    presented: str | None,
    *,
    default_resource: str,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> tuple[str | None, frozenset[str], frozenset[str]]:
    """Validate a JWT, then return capability, allowed tools, and write tools.

    Expired, unsigned, wrong-issuer, and wrong-audience tokens return
    no capability. Claims are accepted only after ``verify_jwt``.
    """
    empty: tuple[str | None, frozenset[str], frozenset[str]] = (None, frozenset(), frozenset())
    if not presented or not looks_like_jwt(presented):
        return empty
    claims = verify_jwt(presented)
    if not claims:
        return empty
    if not audience_ok(claims, audiences(default_resource=default_resource)):
        return empty
    allowed, writes = tools_from_claims(
        claims, read_scopes=read_scopes, write_scopes=write_scopes
    )
    if not allowed:
        return empty
    capability = "admin" if writes else "read"
    return capability, allowed, writes


def classify(
    presented: str | None,
    *,
    default_resource: str,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> str | None:
    """Map a presented JWT to 'admin' | 'read' | None."""
    capability, _allowed, _writes = authorize_token(
        presented,
        default_resource=default_resource,
        read_scopes=read_scopes,
        write_scopes=write_scopes,
    )
    return capability
