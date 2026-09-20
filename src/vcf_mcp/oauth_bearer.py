"""OAuth 2.0 bearer tokens on the HTTP transport.

When vcf-mcp runs as a Streamable HTTP server it is an OAuth *resource
server*. Two kinds of bearer are accepted:

1. The static ``VCF_READ_TOKEN`` / ``VCF_ADMIN_TOKEN`` (see ``server.py``).
2. A JWT access token issued by the authorization server named in
   ``VCF_MCP_OAUTH_ISSUER``. The token must be signed by that issuer's
   JWKS, unexpired, and carry an ``aud`` that names this server (its own
   ``/mcp`` URL or one of ``VCF_MCP_OAUTH_AUDIENCES``).

What the token's ``scope`` may say, any one of which is enough:

* a **tool name** (``vcf_call``, ``vcf_targets`` ...) — the token was
  issued for those tools; write tools give the ``admin`` capability,
  read tools give ``read``;
* the blanket ``tools`` scope — read capability;
* an **intent / permission** scope from an agent gateway
  (``urn:iam:agent:intent:<job>`` by default,
  ``VCF_MCP_OAUTH_INTENT_PREFIX`` to change it) — the gateway in front of
  this server has already mapped the tool the agent called to that job
  and asked its policy engine; this server does not redo that decision
  by tool name. Capability is ``admin``; the gateway strips the tools
  the job does not cover.

That last rule is what makes this server work behind an agent gateway
the same way any third-party MCP server does: verify the token, do not
re-authorize per tool.

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
    "vcf_networks",
    "vcf_storage",
    "vcf_metrics",
)
VCF_WRITE_SCOPES = ("vcf_call", "vcf_task", "vcf_vms")

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
    """True when an agent gateway granted this agent a job on this server."""
    return bool(intent_scopes(claims))


def capability_for(
    claims: dict[str, Any],
    *,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> str | None:
    """Pure decision: 'admin' | 'read' | None from verified claims."""
    writes = list(write_scopes)
    reads = expand_read_scopes(read_scopes)
    if writes and mutating_grant(claims, writes):
        return "admin"
    if grant_ok(claims, reads or writes):
        return "read"
    if intent_grant(claims):
        return "admin"
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


def classify(
    presented: str | None,
    *,
    default_resource: str,
    read_scopes: Iterable[str],
    write_scopes: Iterable[str] = (),
) -> str | None:
    """Map a presented JWT to 'admin' | 'read' | None."""
    if not presented or not looks_like_jwt(presented):
        return None
    claims = verify_jwt(presented)
    if not claims:
        return None
    if not audience_ok(claims, audiences(default_resource=default_resource)):
        return None
    return capability_for(claims, read_scopes=read_scopes, write_scopes=write_scopes)
