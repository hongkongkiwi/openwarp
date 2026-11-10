#!/usr/bin/env python3
"""Check openapi.json against the routes registered in crates/server/src/app.rs.

Fails when the committed contract is stale, when the spec documents a path or
method the server does not serve, when a $ref is missing, or when a path
parameter is not declared. Plain mode reports undocumented routes; --strict
fails on them unless the route is a browser-only or protocol surface listed in
EXCLUDED.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "openapi.json"
MAIN = ROOT / "crates/server/src/app.rs"

# Surfaces that are deliberately outside the machine contract: console assets,
# the OAuth authorization dance, the MCP transport itself, SCIM and the
# browser OIDC/SAML/social callbacks. Machine authentication endpoints stay in
# the contract.
EXCLUDED = {
    "/",
    "/e2e.js",
    "/i18n.js",
    "/auth-v2.js",
    "/libsodium.js",
    "/libsodium-wrappers.js",
    "/metrics",
    "/zxcvbn.js",
    "/hash-wasm.js",
    "/secret-health.js",
    "/enzoic-pairs.js",
    "/lockbox/{lid}",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/authorize/decision",
    "/oauth/token",
    "/oauth/revoke",
    "/mcp",
    "/api/live",
    "/api/auth/register-v2",
    "/api/auth/challenge",
    "/api/auth/login-v2",
    "/api/auth/reset-v2",
    "/api/auth/reset-info",
    "/api/auth/accept-invite-v2",
    "/api/auth/kdf",
    "/api/auth/verify",
    "/api/auth/social/{provider}/start",
    "/api/auth/social/{provider}/callback",
    "/api/auth/oidc/{oid}/start",
    "/api/auth/oidc/callback",
    "/api/auth/saml/{oid}/metadata",
    "/api/auth/saml/{oid}/start",
    "/api/auth/saml/{oid}/acs",
    "/api/auth/ldap",
    "/scim/v2/Users",
    "/scim/v2/Users/{uid}",
    "/scim/v2/Groups",
    "/scim/v2/Groups/{tid}",
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/ResourceTypes",
    "/scim/v2/Schemas",
}


def norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def strip_test_code(src: str) -> str:
    # Drop test-gated modules (#[cfg(test)], #[cfg(all(test,...))], ...) so
    # test-only routers (fixture providers and the like) are not counted as
    # served routes.
    out: list[str] = []
    i = 0
    marker = re.compile(r"#\[cfg\([^\]]*\btest[^\]]*\)\]\s*\nmod\b")
    while True:
        j = marker.search(src, i)
        if j is None:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i : j.start()])
        k = src.find("{", j.start())
        if k < 0:
            return "".join(out)
        depth = 0
        m = k
        while m < len(src):
            if src[m] == "{":
                depth += 1
            elif src[m] == "}":
                depth -= 1
                if depth == 0:
                    break
            m += 1
        i = m + 1


def server_routes() -> dict[str, set[str]]:
    # Routes mounted from their own modules are scanned alongside app.rs so the
    # strict gate sees everything the server serves, not only what app.rs
    # registers inline.
    server = ROOT / "crates/server/src"
    src = "\n".join(
        strip_test_code((server / name).read_text())
        for name in ("app.rs", "webhooks.rs", "ai.rs", "broker.rs")
    )
    routes: dict[str, set[str]] = {}
    pattern = re.compile(
        r'\.route\("([^"]+)"\s*,\s*(.+?)(?=\)\s*(?:\}|;)|\.route\(|\.layer\(|\.with_state\(|\.merge\(|\Z)', re.S
    )
    for m in pattern.finditer(src):
        path, spec = m.group(1), m.group(2)
        methods = {x.upper() for x in re.findall(r"\b(get|post|put|patch|delete)\s*\(", spec)}
        routes.setdefault(norm(path), set()).update(methods)
    return routes


def refs(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str) and v.startswith("#/components/schemas/"):
                out.add(v.split("/")[-1])
            else:
                refs(v, out)
    elif isinstance(node, list):
        for v in node:
            refs(v, out)


def main() -> int:
    strict = "--strict" in sys.argv
    built = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "openapi-build.py"), "--check"],
        capture_output=True,
        text=True,
    )
    if built.returncode != 0:
        sys.stderr.write(built.stdout + built.stderr)
        return 1

    spec = json.loads(SPEC.read_text())
    routes = server_routes()
    errors: list[str] = []
    documented: set[str] = set()
    documented_methods: dict[str, set[str]] = {}

    for path, item in spec.get("paths", {}).items():
        key = norm(path)
        documented.add(key)
        documented_methods.setdefault(key, set()).update(
            m.upper() for m in item if not m.startswith("x-") and m != "parameters"
        )
        if key not in routes:
            errors.append(f"spec documents {path} but the server serves no such route")
            continue
        for method, op in item.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if method.upper() not in routes[key]:
                errors.append(
                    f"spec documents {method.upper()} {path} but the server does not register it"
                )
            params = {p["name"] for p in op.get("parameters", []) if p.get("in") == "path"}
            for want in re.findall(r"\{([^}]+)\}", path):
                if want not in params:
                    errors.append(
                        f"{method.upper()} {path}: path parameter {{{want}}} is not declared"
                    )

    schemas = spec.get("components", {}).get("schemas", {})
    used: set[str] = set()
    refs(spec, used)
    for name in sorted(used - set(schemas)):
        errors.append(f"unresolved schema reference: {name}")

    undocumented = sorted(set(routes) - documented)
    allowed = {norm(p) for p in EXCLUDED}
    uncovered = [p for p in undocumented if p not in allowed]
    unexpected_exclusions = sorted(allowed - set(routes))
    # Method-level coverage: a documented path whose served methods are not all
    # documented is a coverage hole exactly like an undocumented route.
    missing_methods = sorted(
        (path, method)
        for path, served in routes.items()
        if path in documented
        for method in sorted(served - documented_methods.get(path, set()))
    )

    operations = sum(
        1
        for item in spec.get("paths", {}).values()
        for m in item
        if not m.startswith("x-") and m != "parameters"
    )
    print(
        f"spec: {len(spec.get('paths', {}))} paths, {operations} operations, "
        f"{len(schemas)} schemas"
    )
    print(
        f"server: {len(routes)} routes; {len(undocumented)} not in the public contract "
        f"({len(uncovered)} not excluded)"
    )
    if uncovered:
        print("  uncovered: " + ", ".join(uncovered[:20]) + (" ..." if len(uncovered) > 20 else ""))
    if missing_methods:
        print(
            "  undocumented operations: "
            + ", ".join(f"{method} {path}" for path, method in missing_methods[:20])
            + (" ..." if len(missing_methods) > 20 else "")
        )
    if unexpected_exclusions:
        print(
            "  excluded but not served (remove from EXCLUDED): "
            + ", ".join(unexpected_exclusions)
        )
    if strict and uncovered:
        errors.append(f"{len(uncovered)} machine-relevant routes are undocumented")
    if strict and missing_methods:
        errors.append(f"{len(missing_methods)} served operations are undocumented")
    if strict and unexpected_exclusions:
        errors.append("EXCLUDED names a route the server does not serve")
    if errors:
        print("\nERRORS", file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        return 1
    print("openapi contract matches the server routes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
