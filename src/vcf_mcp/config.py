"""Target registry and credential loading.

Every VCF appliance is a *target*: a host, an auth strategy, and one or more
OpenAPI specs describing what it accepts. The registry below is the single
place that knows which is which -- auth.py, client.py and specs.py all read
from it rather than carrying their own host tables.

Nothing site-specific is checked in. Appliance addresses come from
VCF_MCP_<TARGET>_HOST or a hosts file (see hosts.example.json); credentials
come from an existing .env, ideally whichever file is already the rotation
point for the estate. No secret is ever written into this repo, and no secret
value is ever returned by a tool -- config exposes key *names* only.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PKG_ROOT.parent.parent

# The server runs two ways: from a git checkout, and from an installed copy
# (pip, or `uvx` with no install at all). A checkout keeps its files at the
# repo root; an installed copy has no repo root to write to, so it uses the
# platform's config/state directories instead.
IN_CHECKOUT = (PROJECT_ROOT / "pyproject.toml").is_file()
CONFIG_HOME = (
    Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "vcf-mcp"
)
STATE_HOME = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "vcf-mcp"
)


def _site_path(name: str) -> Path:
    """Where a user-owned file lives: repo root in a checkout, else ~/.config."""
    return PROJECT_ROOT / name if IN_CHECKOUT else CONFIG_HOME / name


# Specs are shipped inside the package so an installed copy is self-contained;
# a checkout keeps them at the repo root, where they are easier to update.
_BUNDLED_SPECS = PKG_ROOT / "specs"
SPEC_DIR = Path(
    os.environ.get(
        "VCF_MCP_SPEC_DIR",
        PROJECT_ROOT / "specs" if IN_CHECKOUT else _BUNDLED_SPECS,
    )
)
CACHE_DIR = Path(
    os.environ.get("VCF_MCP_CACHE_DIR", Path.home() / ".cache" / "vcf-mcp")
)
AUDIT_LOG = Path(
    os.environ.get(
        "VCF_MCP_AUDIT_LOG",
        PROJECT_ROOT / "logs" / "vcf-mcp-audit.jsonl"
        if IN_CHECKOUT
        else STATE_HOME / "vcf-mcp-audit.jsonl",
    )
)

DEFAULT_ENV_FILE = str(_site_path(".env"))
DEFAULT_INSTALLER_CREDS = str(_site_path("vcf-installer-credentials.txt"))

# Appliance addresses are site-specific and are never checked in. They come
# from VCF_MCP_<TARGET>_HOST, or from a hosts file (see hosts.example.json).
HOSTS_FILE = Path(os.environ.get("VCF_MCP_HOSTS_FILE", _site_path("hosts.json")))


def _hosts_file_entries() -> dict[str, str]:
    if not HOSTS_FILE.exists():
        return {}
    try:
        data = json.loads(HOSTS_FILE.read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{HOSTS_FILE} is not readable JSON: {exc}") from exc
    hosts = data.get("hosts", data)
    return {str(k): str(v).strip() for k, v in hosts.items() if str(v).strip()}


_HOSTS = _hosts_file_entries()


def host_env_var(name: str) -> str:
    return f"VCF_MCP_{name.upper().replace('-', '_')}_HOST"


def _host(name: str) -> str:
    """Address for one target, or "" if this site has not configured it."""
    return os.environ.get(host_env_var(name), "").strip() or _HOSTS.get(name, "")


@dataclass(frozen=True)
class Target:
    """One addressable VCF appliance."""

    name: str
    product: str
    host: str
    auth: str  # see auth.py: vcf_token | vcenter_session | nsx_basic | ops_token
    specs: tuple[str, ...]
    api_root: str = ""
    user_env: tuple[str, ...] = ()
    password_env: tuple[str, ...] = ()
    default_user: str = ""
    notes: str = ""
    # Paths that never carry auth (the token endpoints themselves).
    unauthenticated: tuple[str, ...] = field(default_factory=tuple)
    # Some appliances have no standing credential of their own: VCF generates
    # their password and keeps it in another appliance's credential store.
    # Set to (target_name, resourceType) to fetch it at auth time.
    credential_via: tuple[str, str] | None = None


# What each appliance is and how it authenticates -- verified against a live
# 9.1 estate. Only the addresses are site-local, and those are resolved above.
TARGETS: dict[str, Target] = {
    "sddc": Target(
        name="sddc",
        product="SDDC Manager",
        host=_host("sddc"),
        auth="vcf_token",
        specs=("sddc-manager-openapi.json", "sddc-lcm-openapi.yaml", "fleet-lcm-openapi.yaml"),
        default_user="administrator@vsphere.local",
        # NSX_ADMIN_PASSWORD first: it is the value the whole fleet is built
        # with, and SDDC_MANAGER_PASSWORD is often stale. Verified live.
        password_env=("NSX_ADMIN_PASSWORD", "SDDC_MANAGER_PASSWORD", "VCF_APPLIANCE_PASSWORD"),
        unauthenticated=("/v1/tokens",),
        notes="Owns the estate after bring-up: domains, clusters, hosts, certs, bundles, upgrades.",
    ),
    "installer": Target(
        name="installer",
        product="VCF Installer",
        host=_host("installer"),
        auth="vcf_token",
        specs=("vcf-installer-openapi.json",),
        default_user="admin@local",
        password_env=("NSX_ADMIN_PASSWORD", "VCF_INSTALLER_PASSWORD"),
        unauthenticated=("/v1/tokens",),
        notes="Bring-up and SDDC spec validation. Largely idle once the estate is up.",
    ),
    "vcenter": Target(
        name="vcenter",
        product="vCenter Server",
        host=_host("vcenter"),
        auth="vcenter_session",
        specs=("vcenter.yaml",),
        default_user="administrator@vsphere.local",
        password_env=("NSX_ADMIN_PASSWORD", "NESTED_VCSA_PASSWORD"),
        unauthenticated=("/api/session",),
        notes="VM, host, datastore, vSAN and content-library control plane.",
    ),
    "nsx": Target(
        name="nsx",
        product="NSX Manager",
        host=_host("nsx"),
        auth="nsx_basic",
        specs=("nsx_policy_api.yaml", "nsx_api.yaml"),
        default_user="admin",
        password_env=("NSX_ADMIN_PASSWORD",),
        notes="VIP address. Policy API (/policy/api/v1) is the modern surface; /api/v1 is the manager API.",
    ),
    "ops": Target(
        name="ops",
        product="VCF Operations",
        host=_host("ops"),
        auth="ops_token",
        specs=("vcf-operations-openapi.json", "log-management-openapi.json"),
        default_user="admin",
        password_env=("NSX_ADMIN_PASSWORD",),
        unauthenticated=("/suite-api/api/auth/token/acquire",),
        notes="Alerts, metrics, capacity, log management. Most paths live under /suite-api.",
    ),
    "avi": Target(
        name="avi",
        product="Avi Load Balancer (NSX ALB)",
        host=_host("avi"),
        auth="avi_session",
        specs=tuple(
            sorted(
                f"avi/{p.name}"
                for p in (SPEC_DIR / "avi").glob("*.yaml")
            )
        ),
        default_user="admin",
        # The password is VCF-generated and is NOT the appliance password; it
        # lives in SDDC Manager's credential store (RUNBOOK §Prerequisites).
        # VCF_MCP_AVI_PASSWORD still overrides for a non-VCF-managed Avi.
        password_env=(),
        credential_via=("sddc", "NSX_ALB"),
        unauthenticated=("/login", "/api/initial-data"),
        notes=(
            "Single controller. Basic auth is rejected -- session "
            "login only. Credential fetched at runtime from SDDC Manager "
            "(resourceType NSX_ALB), never stored."
        ),
    ),
    "vsan-dp": Target(
        name="vsan-dp",
        product="vSAN Data Protection",
        host=_host("vsan-dp"),
        auth="vcenter_session",
        specs=("vsan-data-protection-openapi.yaml",),
        default_user="administrator@vsphere.local",
        password_env=("NSX_ADMIN_PASSWORD", "NESTED_VCSA_PASSWORD"),
        unauthenticated=("/api/session",),
        notes="Snapshot/protection-group API served by the vCenter appliance.",
    ),
}

_PLACEHOLDER = re.compile(r"CHANGEME|^\s*$")


def env_file() -> Path:
    return Path(os.environ.get("VCF_MCP_ENV_FILE", DEFAULT_ENV_FILE))


def load_env() -> dict[str, str]:
    """Parse the KEY=value .env, tolerating quotes and comments.

    Real process environment wins, so a value can always be overridden without
    editing the shared lab file.
    """
    out: dict[str, str] = {}
    path = env_file()
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip("'\"")
    for key in os.environ:
        if key.startswith(("VCF_", "NSX_", "SDDC_", "NESTED_", "VSPHERE_")):
            out[key] = os.environ[key]
    return out


# Hard cap on authentication attempts per target. vSphere SSO locks an account
# after a handful of consecutive failures, so trying every key in the .env is
# not a harmless fallback -- it is a way to lock administrator@vsphere.local
# out of the estate. Order the candidates well and stop early instead.
MAX_AUTH_ATTEMPTS = 3


def credentials(target: Target) -> list[tuple[str, str, str]]:
    """Candidate (username, password, source_key) pairs, best guess first.

    The lab's .env carries several appliance passwords and not all of them are
    current -- SDDC_MANAGER_PASSWORD in particular can be stale where
    NSX_ADMIN_PASSWORD is the value actually deployed (NSX has the strictest
    complexity rules, so the fleet is set to a password NSX accepts). The
    order in each target's `password_env` reflects what is proven to work.

    Never returns a value; the caller is the only thing that sees a secret.
    """
    env = load_env()
    users = [target.default_user]
    for key in target.user_env:
        if env.get(key) and not _PLACEHOLDER.search(env[key]):
            users.insert(0, env[key])
    if target.auth == "vcf_token" and "admin@local" not in users:
        # Local fallback account. Second, because it does not always carry the
        # same roles as the SSO administrator.
        users.append("admin@local")

    override = f"VCF_MCP_{target.name.upper().replace('-', '_')}_PASSWORD"
    passwords: list[tuple[str, str]] = []
    seen_values: set[str] = set()
    for key in (override, *target.password_env):
        value = env.get(key, "")
        if value and not _PLACEHOLDER.search(value) and value not in seen_values:
            seen_values.add(value)
            passwords.append((value, key))

    if target.name == "installer":
        user_i, pw_i = _installer_creds_file()
        if pw_i and pw_i not in seen_values:
            seen_values.add(pw_i)
            passwords.insert(0, (pw_i, "build/vcf-installer-credentials.txt"))
            if user_i and user_i not in users:
                users.insert(0, user_i)

    if not passwords:
        if target.credential_via:
            # No local password is expected: auth fetches it at runtime from
            # the credential store named here (e.g. Avi's from SDDC Manager).
            return []
        keys = ", ".join((override, *target.password_env))
        raise RuntimeError(
            f"no usable password for target '{target.name}'. Looked for {keys} in "
            f"{env_file()} (and the process environment). Values that are empty or "
            f"contain CHANGEME are ignored."
        )

    # Password varies fastest: a wrong password is the likely failure, not a
    # wrong username.
    candidates = [
        (user, password, source) for password, source in passwords for user in users
    ]
    return candidates[:MAX_AUTH_ATTEMPTS]


def credential(target: Target) -> tuple[str, str, str]:
    """The single best credential guess, for schemes that cannot retry."""
    return credentials(target)[0]


def _installer_creds_file() -> tuple[str, str]:
    """Parse the generated installer credentials file, if present.

    Tolerant of layout, matching the bring-up scripts that write it. The value is
    only ever returned to the caller, never logged.
    """
    path = Path(os.environ.get("VCF_MCP_INSTALLER_CREDS", DEFAULT_INSTALLER_CREDS))
    if not path.exists():
        return "", ""
    creds: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9 _@.\-]+?)\s*[:=]\s*(.+)$", line)
        if match:
            creds[match.group(1).strip().lower()] = match.group(2).strip()
    for key in ("admin@local", "admin", "admin password", "admin@local password", "password"):
        if creds.get(key):
            return ("admin@local", creds[key])
    return "", ""


def get_target(name: str) -> Target:
    key = (name or "").strip().lower()
    if key not in TARGETS:
        known = ", ".join(sorted(TARGETS))
        raise KeyError(f"unknown target '{name}'. Known targets: {known}")
    return TARGETS[key]


def require_host(target: Target) -> str:
    """The target's address, or a failure that says exactly how to set it.

    Addresses are site-local and deliberately absent from the repo, so an
    unconfigured target must fail loudly rather than build a request against
    an empty host.
    """
    if target.host:
        return target.host
    raise RuntimeError(
        f"no address configured for target '{target.name}' ({target.product}). "
        f"Set {host_env_var(target.name)}, or add a \"{target.name}\" entry to "
        f"{HOSTS_FILE} (copy hosts.example.json to start)."
    )


def verify_tls() -> bool:
    """Self-signed certs on an island network: off by default, opt-in to enforce."""
    return os.environ.get("VCF_MCP_VERIFY_TLS", "0").lower() in ("1", "true", "yes")
