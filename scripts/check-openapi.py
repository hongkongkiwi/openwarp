#!/usr/bin/env python3
"""Check openapi.json against the routes registered in crates/server/src/app.rs.

Fails when the spec documents a path or method the server does not serve, when a
$ref is missing, or when a path parameter is not declared. Routes the spec does
not cover are reported but do not fail, so the public contract can lag internal
or browser-only endpoints deliberately.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "openapi.json"
MAIN = ROOT / "crates/server/src/app.rs"

def norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)

def server_routes() -> dict[str, set[str]]:
    src = MAIN.read_text()
    routes: dict[str, set[str]] = {}
    pattern = re.compile(r'\.route\("([^"]+)"\s*,\s*(.+?)(?=\.route\(|\.layer\(|\.with_state\(|\Z)', re.S)
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
    spec = json.loads(SPEC.read_text())
    routes = server_routes()
    errors: list[str] = []
    documented: set[str] = set()

    for path, item in spec.get("paths", {}).items():
        key = norm(path)
        documented.add(key)
        if key not in routes:
            errors.append(f"spec documents {path} but the server serves no such route")
            continue
        for method, op in item.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if method.upper() not in routes[key]:
                errors.append(f"spec documents {method.upper()} {path} but the server does not register it")
            params = {p["name"] for p in op.get("parameters", []) if p.get("in") == "path"}
            for want in re.findall(r"\{([^}]+)\}", path):
                if want not in params:
                    errors.append(f"{method.upper()} {path}: path parameter {{{want}}} is not declared")

    schemas = spec.get("components", {}).get("schemas", {})
    used: set[str] = set()
    refs(spec, used)
    for name in sorted(used - set(schemas)):
        errors.append(f"unresolved schema reference: {name}")

    undocumented = sorted(set(routes) - documented)
    print(f"spec: {len(spec.get('paths', {}))} paths, {sum(1 for p in spec.get('paths', {}).values() for m in p if not m.startswith('x-') and m != 'parameters')} operations, {len(schemas)} schemas")
    print(f"server: {len(routes)} routes; {len(undocumented)} not in the public contract")
    if undocumented:
        print("  not documented (allowed): " + ", ".join(undocumented[:12]) + (" ..." if len(undocumented) > 12 else ""))
    if errors:
        print("\nERRORS", file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        return 1
    print("openapi contract matches the server routes")
    return 0

if __name__ == "__main__":
    sys.exit(main())
