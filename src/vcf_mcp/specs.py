"""OpenAPI index: search and describe across every vendored VCF spec.

The estate exposes well over a thousand operations. Exposing them as one MCP
tool each would blow the context window before the first question got asked,
so instead the specs are indexed once into a compact record per operation
(method, real path, operationId, summary, tags) and searched on demand. Full
schemas are only ever resolved for the one operation a caller asks about.

Two dialects are handled: OpenAPI 3.x (SDDC Manager, Installer, Operations,
vCenter) and Swagger 2.0 (the NSX policy and manager APIs). The important
difference for us is where the base path lives and how a request body is
declared -- both normalised below so callers never have to care.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import config

try:  # libyaml is 10-20x faster and these files are large
    from yaml import CSafeLoader as _Loader
except ImportError:  # pragma: no cover - fallback for a build without libyaml
    from yaml import SafeLoader as _Loader

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

_docs: dict[str, dict] = {}
_doc_lock = threading.Lock()
_index: list[dict] | None = None
_index_lock = threading.Lock()

# Which target(s) serve each spec file -- inverted from the target registry.
_SPEC_TARGETS: dict[str, list[str]] = {}
for _name, _target in config.TARGETS.items():
    for _spec in _target.specs:
        _SPEC_TARGETS.setdefault(_spec, []).append(_name)


def load_doc(spec_file: str) -> dict:
    """Parse and memoise one spec document."""
    with _doc_lock:
        if spec_file in _docs:
            return _docs[spec_file]
    path = config.SPEC_DIR / spec_file
    if not path.exists():
        raise FileNotFoundError(f"spec not found: {path}")
    text = path.read_text()
    doc = json.loads(text) if path.suffix == ".json" else yaml.load(text, Loader=_Loader)
    with _doc_lock:
        _docs[spec_file] = doc
    return doc


def base_path(doc: dict) -> str:
    """The prefix that turns a spec path into a real request path.

    Swagger 2.0 states it directly. OpenAPI 3 hides it in the first server
    entry, which may be a bare path ("/suite-api") or a full URL whose path
    component is what matters ("https://{host}/api" -> "/api").
    """
    if doc.get("swagger", "").startswith("2"):
        return (doc.get("basePath") or "").rstrip("/")
    servers = doc.get("servers") or []
    if not servers:
        return ""
    url = str(servers[0].get("url", ""))
    prefix = url if url.startswith("/") else urlsplit(url).path
    prefix = prefix.rstrip("/")
    return "" if prefix in ("/", "") else prefix


# Bump when the shape of an index entry changes, so old caches are discarded.
_INDEX_VERSION = 3


def _fingerprint() -> str:
    """Cache key over the spec files themselves, so edits invalidate cleanly."""
    parts = [f"v{_INDEX_VERSION}"]
    for spec_file in sorted(_SPEC_TARGETS):
        path = config.SPEC_DIR / spec_file
        if path.exists():
            stat = path.stat()
            parts.append(f"{spec_file}:{stat.st_size}:{int(stat.st_mtime)}")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def index() -> list[dict]:
    """The full operation index, built once and cached to disk."""
    global _index
    with _index_lock:
        if _index is not None:
            return _index
    cache_file = config.CACHE_DIR / f"index-{_fingerprint()}.json"
    entries: list[dict] | None = None
    if cache_file.exists():
        try:
            entries = json.loads(cache_file.read_text())
        except (OSError, ValueError):
            entries = None
    if entries is None:
        entries = build_index()
        try:
            config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(entries))
            for stale in config.CACHE_DIR.glob("index-*.json"):
                if stale != cache_file:
                    stale.unlink(missing_ok=True)
        except OSError:
            pass
    with _index_lock:
        _index = entries
    return entries


def build_index() -> list[dict]:
    entries: list[dict] = []
    _add_entry.seen = {}  # fresh dedupe state per build
    for spec_file, targets in sorted(_SPEC_TARGETS.items()):
        try:
            doc = load_doc(spec_file)
        except FileNotFoundError:
            continue
        prefix = base_path(doc)
        title = (doc.get("info") or {}).get("title", spec_file)
        for spec_path, item in (doc.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            shared = item.get("parameters") or []
            for method, operation in item.items():
                if method not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                params = list(shared) + list(operation.get("parameters") or [])
                _add_entry(entries,
                    {
                        "targets": targets,
                        "spec": spec_file,
                        "api": title,
                        "op": operation.get("operationId") or "",
                        "method": method.upper(),
                        "path": prefix + spec_path,
                        "spec_path": spec_path,
                        "summary": (operation.get("summary") or "").strip(),
                        "tags": operation.get("tags") or [],
                        "deprecated": bool(operation.get("deprecated")),
                        # Depth *within* the API, i.e. excluding the base path,
                        # so a shallow NSX policy path is not punished for
                        # living under /policy/api/v1.
                        "depth": spec_path.count("/"),
                        "params": [p.get("name", "") for p in params if isinstance(p, dict)],
                        "has_body": _has_body(operation, params),
                    }
                )
    return entries


def _add_entry(entries: list[dict], entry: dict) -> None:
    """Append, deduplicating identical (target, method, path) declarations.

    Avi vendors one spec per object type and each file re-declares the paths
    of related objects, so /api/upgradestatusinfo appears in three files.
    Keep the declaration from the file named after the resource -- it is the
    authoritative one -- and otherwise first-in wins.
    """
    key = (tuple(entry["targets"]), entry["method"], entry["path"])
    existing = _add_entry.seen.get(key)
    if existing is None:
        _add_entry.seen[key] = entry
        entries.append(entry)
        return
    resource = entry["path"].split("?")[0].strip("/").split("/")
    resource = (resource[1] if len(resource) > 1 else resource[0]).replace("-", "").lower()
    own_file = Path(entry["spec"]).stem.lower()
    if own_file == resource and Path(existing["spec"]).stem.lower() != resource:
        existing.update(entry)  # replace in place; list order is preserved


_add_entry.seen = {}


def _has_body(operation: dict, params: list) -> bool:
    if operation.get("requestBody"):
        return True
    return any(isinstance(p, dict) and p.get("in") == "body" for p in params)


def search(
    query: str,
    target: str | None = None,
    method: str | None = None,
    limit: int = 25,
    include_deprecated: bool = False,
) -> dict:
    """Rank operations against a free-text query.

    Returns {"results": [...], "hidden_deprecated": [...]} -- the second list
    names deprecated operations that matched well but were filtered out, so a
    caller chasing a legacy path learns it is legacy instead of concluding
    the operation does not exist.

    Scoring favours, in order: the operationId, the path, the tag, then the
    summary -- because callers search for the thing they want to do ("expand
    cluster", "rotate certificate") and those words land in identifiers far
    more reliably than in prose.
    """
    tokens = [t for t in _tokenize(query) if t]
    wanted_method = (method or "").upper().strip()
    results: list[tuple[float, dict]] = []
    hidden_deprecated: list[tuple[float, dict]] = []

    for entry in index():
        if target and target not in entry["targets"]:
            continue
        if wanted_method and entry["method"] != wanted_method:
            continue
        score = _score(entry, tokens, query)
        if score <= 0:
            continue
        if entry["deprecated"] and not include_deprecated:
            # Not shown, but not silently erased either: a caller who found a
            # legacy path in old docs deserves to learn it is legacy, not to
            # conclude the index is missing it.
            hidden_deprecated.append((score, entry))
            continue
        results.append((score, entry))

    results.sort(key=lambda pair: (-pair[0], pair[1]["path"]))
    rendered = [
        {
            "target": entry["targets"][0],
            "targets": entry["targets"],
            "operationId": entry["op"],
            "method": entry["method"],
            "path": entry["path"],
            "summary": entry["summary"],
            "tags": entry["tags"],
            "has_body": entry["has_body"],
            "api": entry["api"],
            "score": round(score, 2),
            **({"deprecated": True} if entry["deprecated"] else {}),
        }
        for score, entry in results[: max(1, limit)]
    ]

    top_score = rendered[0]["score"] if rendered else 0
    hidden_deprecated.sort(key=lambda pair: -pair[0])
    # Only worth surfacing when a hidden legacy operation scored well enough
    # that the caller might actually have been looking for it.
    notable = [
        {"method": e["method"], "path": e["path"], "operationId": e["op"], "deprecated": True}
        for score, e in hidden_deprecated[:5]
        if score >= max(2.0, top_score * 0.5)
    ]
    return {"results": rendered, "hidden_deprecated": notable}


_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

# Words that carry no discriminating power in a spec where every path is an API.
_STOP = {"a", "an", "the", "of", "for", "to", "in", "on", "with", "and", "or", "by", "api", "all"}

# The vocabulary a person uses is not always the vocabulary the spec uses.
# Kept deliberately small and VCF-specific: each entry below reflects a real
# naming split in these specs, not a general-purpose thesaurus.
_SYNONYMS = {
    "vm": {"vm", "virtualmachine"},
    "vms": {"vm", "virtualmachine"},  # too short for the stemmer to singularise
    "virtual": {"virtual", "vm"},
    "machine": {"machine", "vm"},
    "esxi": {"esxi", "esx", "host"},
    "esx": {"esx", "esxi", "host"},
    "server": {"server", "host"},
    "add": {"add", "create", "commission", "expand"},
    # Avi operationIds are literally "POST /pool" -- the method IS the verb.
    "create": {"create", "add", "post"},
    "delete": {"delete", "remove"},
    "remove": {"remove", "delete", "decommission", "shrink"},
    "list": {"list", "get", "retrieve", "query"},
    "show": {"show", "get", "retrieve"},
    "workload": {"workload", "domain"},
    "cert": {"cert", "certificate"},
    "creds": {"creds", "credential"},
    "password": {"password", "credential"},
    "t1": {"t1", "tier"},
    "t0": {"t0", "tier"},
    "upgrade": {"upgrade", "update", "lcm"},
    "patch": {"patch", "bundle", "upgrade"},
}


def _stem(word: str) -> str:
    """Crude singular form. `domains` -> `domain`, `clusters` -> `cluster`.

    Specs mix plural collection nouns with singular identifiers constantly
    (`getDomains` vs `/v1/domains/{id}`), and a user's query picks whichever
    reads naturally. Matching on the stem removes that coin flip.
    """
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 4 and word.endswith(("ses", "xes", "ches", "shes")):
        return word[:-2]  # statuses -> status, aliases -> alias
    # "status", "analysis" and "address" are not plurals; stripping their final
    # s would also stop `status` matching `statuses`, which stems back to it.
    if len(word) > 3 and word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def _tokenize(text: str) -> list[str]:
    """Split on non-alphanumerics *and* camelCase humps, then stem.

    Without the hump split, `checkAddHostEvc` is a single token and a search
    for "host" cannot match it -- which is most of an OpenAPI spec's signal,
    since operationIds are the most reliable description of intent.
    """
    return [_stem(word.lower()) for word in _WORD.findall(text or "")]


def _expand(tokens: list[str]) -> list[set[str]]:
    groups = []
    for token in tokens:
        if token in _STOP:
            continue
        synonyms = _SYNONYMS.get(token, {token})
        groups.append({_stem(s) for s in synonyms})
    return groups


def _score(entry: dict, tokens: list[str], raw_query: str) -> float:
    groups = _expand(tokens)
    if not groups:
        return 0.0

    op_tokens = set(_tokenize(entry["op"]))
    path_tokens = set(_tokenize(entry["path"]))
    tag_tokens = set(_tokenize(" ".join(entry["tags"])))
    summary_tokens = set(_tokenize(entry["summary"]))
    op_lower = entry["op"].lower()
    path_lower = entry["path"].lower()
    summary_lower = entry["summary"].lower()

    score = 0.0
    matched = 0
    explained: set[str] = set()
    for group in groups:
        hit = 0.0
        if group & op_tokens:
            hit = 4.0
            explained |= group & op_tokens
        elif group & path_tokens:
            hit = 3.2
        elif group & tag_tokens:
            hit = 2.6
        elif group & summary_tokens:
            hit = 2.0
        elif any(token in op_lower or token in path_lower for token in group):
            hit = 1.2  # substring, e.g. "cert" inside "certificates"
        elif any(token in summary_lower for token in group):
            hit = 0.8
        if hit:
            matched += 1
            score += hit

    if not matched:
        return 0.0

    # Every token landing somewhere is a far stronger signal than one of five.
    coverage = matched / len(groups)
    score *= 0.25 + 0.75 * coverage
    if coverage == 1.0:
        score += 2.0

    # The reverse direction matters just as much: how much of the operation
    # does the query actually account for? "get alerts" explains all of
    # `getAlerts` but less than half of `getAlertDefinitionById`, and the
    # former is what was asked for. Without this, any operation whose name
    # merely *starts* with the query wins on raw hit count.
    if op_tokens:
        precision = len(explained & op_tokens) / len(op_tokens)
        score *= 0.55 + 0.45 * precision

    if raw_query.strip().lower() == op_lower:
        score += 30.0

    # An exact resource-name hit beats a substring hit: "virtual service"
    # concatenates to "virtualservice", which IS /api/virtualservice's segment
    # but merely appears inside /api/debugvirtualservice.
    fused = "".join(t for t in tokens if t not in _STOP and t not in ("list", "get", "show", "create", "delete", "update"))
    segments = [
        s.replace("-", "").replace("_", "").lower().rstrip("s")
        for s in entry["path"].split("?")[0].strip("/").split("/")
        if not s.startswith("{")
    ]
    if fused and (fused in segments or fused.rstrip("s") in segments or _stem(fused) in segments):
        score += 2.5

    # Deeply nested paths are specific sub-resources; a plain question about
    # "clusters" means /v1/clusters, not .../clusters/{id}/x/y/z/status.
    score -= 0.8 * max(0, entry.get("depth", entry["path"].count("/")) - 2)
    # A collection endpoint is what "list the X" almost always means.
    if "{" not in entry["path"]:
        score += 1.2

    # NSX federation mirrors every policy path under /global-infra. This lab,
    # like most, is not federated -- keep them findable but never first.
    if "/global-infra" in path_lower:
        score -= 3.5
    # GETs are the safe, common case; nudge them up on otherwise equal scores.
    if entry["method"] == "GET":
        score += 0.4
    return score


def find(
    target: str | None = None,
    operation_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
) -> dict:
    """Locate exactly one indexed operation, by id or by method+path."""
    candidates = index()
    if target:
        candidates = [e for e in candidates if target in e["targets"]]
    if operation_id:
        wanted = operation_id.strip().lower()
        matches = [e for e in candidates if e["op"].lower() == wanted]
        if not matches:
            near = [e for e in candidates if wanted in e["op"].lower()][:8]
            hint = ", ".join(f"{e['op']}" for e in near)
            raise LookupError(
                f"no operation with id '{operation_id}'"
                + (f". Did you mean: {hint}" if hint else "")
            )
    else:
        if not path:
            raise LookupError("give either operation_id, or method and path")
        wanted_method = (method or "GET").upper()
        normalised = path if path.startswith("/") else "/" + path
        matches = [
            e for e in candidates if e["method"] == wanted_method and e["path"] == normalised
        ]
        if not matches:
            matches = [
                e
                for e in candidates
                if e["method"] == wanted_method and _template_match(e["path"], normalised)
            ]
        if not matches:
            raise LookupError(
                f"no operation {wanted_method} {normalised}"
                + (f" on target '{target}'" if target else "")
                + ". Use vcf_search_api to find the right one."
            )
    matches.sort(key=lambda e: (e["deprecated"], len(e["path"])))
    return matches[0]


def _template_match(template: str, actual: str) -> bool:
    """Does /v1/hosts/{id} describe /v1/hosts/abc-123 ?"""
    left, right = template.strip("/").split("/"), actual.strip("/").split("/")
    if len(left) != len(right):
        return False
    return all(a.startswith("{") or a == b for a, b in zip(left, right))


def describe(entry: dict, depth: int = 3, max_properties: int = 60) -> dict:
    """Full, resolved signature for one operation."""
    doc = load_doc(entry["spec"])
    item = (doc.get("paths") or {}).get(entry["spec_path"], {})
    operation = item.get(entry["method"].lower(), {})
    resolver = _Resolver(doc)

    params = [
        resolver.resolve(p) for p in (item.get("parameters") or []) if isinstance(p, dict)
    ] + [resolver.resolve(p) for p in (operation.get("parameters") or []) if isinstance(p, dict)]

    described_params = []
    body_schema = None
    body_required = False
    body_content = "application/json"

    for param in params:
        if param.get("in") == "body":  # Swagger 2.0 body parameter
            body_schema = resolver.shape(param.get("schema"), depth, max_properties)
            body_required = bool(param.get("required"))
            continue
        schema = param.get("schema") or {k: param[k] for k in ("type", "enum", "format") if k in param}
        described_params.append(
            {
                "name": param.get("name"),
                "in": param.get("in"),
                "required": bool(param.get("required")),
                "description": _trim(param.get("description")),
                "schema": resolver.shape(schema, 2, 30),
            }
        )

    request_body = operation.get("requestBody")
    if request_body:
        request_body = resolver.resolve(request_body)
        body_required = bool(request_body.get("required"))
        content = request_body.get("content") or {}
        body_content = "application/json" if "application/json" in content else next(iter(content), "")
        media = content.get(body_content) or {}
        body_schema = resolver.shape(media.get("schema"), depth, max_properties)

    responses = {}
    for status, response in (operation.get("responses") or {}).items():
        response = resolver.resolve(response) if isinstance(response, dict) else {}
        schema = response.get("schema")
        if not schema:
            content = response.get("content") or {}
            media = content.get("application/json") or (
                next(iter(content.values()), {}) if content else {}
            )
            schema = media.get("schema") if isinstance(media, dict) else None
        responses[str(status)] = {
            "description": _trim(response.get("description")),
            "schema": resolver.shape(schema, min(depth, 2), 40) if schema else None,
        }

    return {
        "target": entry["targets"][0],
        "targets": entry["targets"],
        "api": entry["api"],
        "operationId": entry["op"],
        "method": entry["method"],
        "path": entry["path"],
        "summary": entry["summary"],
        "description": _trim(operation.get("description"), 1200),
        "tags": entry["tags"],
        "deprecated": entry["deprecated"],
        "parameters": described_params,
        "request_body": {
            "required": body_required,
            "content_type": body_content,
            "schema": body_schema,
        }
        if body_schema is not None
        else None,
        "responses": responses,
    }


class _Resolver:
    """Resolves $ref and flattens allOf, with cycle and depth protection.

    VCF schemas reference each other freely and NSX in particular nests
    allOf chains several deep; rendering them raw would produce megabytes.
    `shape` returns a compact, human-readable approximation instead.
    """

    def __init__(self, doc: dict):
        self.doc = doc

    def resolve(self, node: Any, seen: set[str] | None = None) -> Any:
        seen = seen or set()
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen or not isinstance(ref, str) or not ref.startswith("#/"):
                return {"$ref": ref, "note": "unresolved (cyclic or external)"}
            seen.add(ref)
            target: Any = self.doc
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    return {"$ref": ref, "note": "unresolved"}
                target = target[part]
            merged = {k: v for k, v in node.items() if k != "$ref"}
            node = {**target, **merged} if isinstance(target, dict) else target
        return node

    def shape(self, schema: Any, depth: int, max_properties: int, seen: set[str] | None = None) -> Any:
        if schema is None:
            return None
        seen = set(seen or ())
        ref = schema.get("$ref") if isinstance(schema, dict) else None
        if isinstance(ref, str) and ref in seen:
            # Already expanded higher up this branch: name it and stop, rather
            # than recursing forever through a self-referential schema.
            return {"type": ref.rsplit("/", 1)[-1], "note": "recursive reference"}
        # Resolve with a *fresh* chain -- `seen` tracks ancestors of this node,
        # and pre-seeding it with this node's own ref would refuse to expand it.
        schema = self.resolve(schema)
        if isinstance(ref, str):
            seen.add(ref)
        if not isinstance(schema, dict):
            return schema

        for key in ("allOf", "anyOf", "oneOf"):
            if key in schema:
                schema = self._combine(schema, key, seen)
                break

        if depth <= 0:
            kind = schema.get("type") or "object"
            expandable = bool(schema.get("properties") or schema.get("items"))
            leaf = {"type": kind}
            if schema.get("enum"):
                leaf["enum"] = schema["enum"][:25]
            # Only claim truncation where there is genuinely more to show.
            return {**leaf, "note": "truncated -- raise depth to expand"} if expandable else leaf

        kind = schema.get("type")
        out: dict[str, Any] = {}
        if kind:
            out["type"] = kind
        for key in ("format", "enum", "default", "example"):
            if key in schema:
                out[key] = schema[key] if key != "enum" else schema[key][:25]
        if schema.get("description"):
            out["description"] = _trim(schema["description"])
            if "enum" not in out:
                # vCenter's vAPI specs declare enums as prose: "Possible
                # values:\n - `NSXT_CONTAINER_PLUGIN`: ...". The value list is
                # usually the single decisive fact about the field, so lift it
                # out of the prose into a real enum.
                prose = _prose_enum(schema["description"])
                if prose:
                    out["enum"] = prose

        if schema.get("properties"):
            required = set(schema.get("required") or [])
            properties = {}
            for count, (name, sub) in enumerate(schema["properties"].items()):
                if count >= max_properties:
                    properties["..."] = f"{len(schema['properties']) - max_properties} more properties"
                    break
                rendered = self.shape(sub, depth - 1, max_properties, seen)
                if name in required:
                    if isinstance(rendered, dict):
                        rendered = {"required": True, **rendered}
                    else:
                        rendered = {"required": True, "type": rendered}
                properties[name] = rendered
            out["type"] = out.get("type", "object")
            out["properties"] = properties
            if required:
                out["required"] = sorted(required)
        elif "items" in schema:
            out["type"] = out.get("type", "array")
            out["items"] = self.shape(schema["items"], depth - 1, max_properties, seen)
        elif "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
            out["type"] = out.get("type", "object")
            out["additionalProperties"] = self.shape(
                schema["additionalProperties"], depth - 1, max_properties, seen
            )
        return out or {"type": "object"}

    def _combine(self, schema: dict, key: str, seen: set[str]) -> dict:
        """Flatten allOf into one object; keep anyOf/oneOf as a labelled union."""
        parts = [self.resolve(p, set(seen)) for p in schema[key] if isinstance(p, dict)]
        rest = {k: v for k, v in schema.items() if k != key}
        if key == "allOf":
            merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if part.get("properties"):
                    merged["properties"].update(part["properties"])
                merged["required"].extend(part.get("required") or [])
                for field in ("description", "type", "items", "enum"):
                    if field in part and field not in merged:
                        merged[field] = part[field]
            if not merged["properties"]:
                merged.pop("properties")
            merged["required"] = sorted(set(merged["required"]))
            if not merged["required"]:
                merged.pop("required")
            return {**merged, **rest}
        return {**rest, "type": rest.get("type", "object"), key: parts}


_PROSE_ENUM_HEADER = re.compile(r"Possible values\s*:", re.IGNORECASE)
_PROSE_ENUM_VALUE = re.compile(r"^\s*-\s*`([A-Z][A-Z0-9_]*)`\s*:", re.MULTILINE)


def _prose_enum(description: str) -> list[str] | None:
    """Extract enum values a vAPI spec wrote as documentation prose.

    Only the section after "Possible values:" is scanned, and only lines of
    the exact `- \\`CONSTANT\\`:` shape count, so ordinary backticked words in
    a description cannot masquerade as values.
    """
    match = _PROSE_ENUM_HEADER.search(description or "")
    if not match:
        return None
    values = _PROSE_ENUM_VALUE.findall(description[match.end() :])
    return values[:25] or None


def _trim(text: Any, limit: int = 300) -> str | None:
    if not text:
        return None
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[:limit] + "..."


def stats() -> list[dict]:
    """Per-spec operation counts, for the targets tool."""
    counts: dict[str, dict] = {}
    for entry in index():
        row = counts.setdefault(
            entry["spec"], {"spec": entry["spec"], "api": entry["api"], "operations": 0}
        )
        row["operations"] += 1
    return sorted(counts.values(), key=lambda r: -r["operations"])
