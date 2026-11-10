#!/usr/bin/env python3
"""Assemble openapi.json from the per-tag fragments under openapi/.

The contract is too large to edit as one file: every group of endpoints lives in
openapi/paths/<group>.json, every schema group in openapi/schemas/<group>.json,
and openapi/base.json holds the document metadata. Run this script after an
edit; CI runs `--check` to reject a stale committed contract.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "openapi"
OUT = ROOT / "openapi.json"


def merge_dir(directory: Path, what: str) -> dict:
    merged: dict = {}
    origin: dict = {}
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            raise SystemExit(f"{path}: expected a JSON object")
        for key, value in data.items():
            if key in merged and merged[key] != value:
                raise SystemExit(
                    f"{what} {key!r} is defined differently in {origin[key]} and {path}"
                )
            merged[key] = value
            origin[key] = path
    return merged


def build() -> dict:
    spec = json.loads((SRC / "base.json").read_text())
    spec["paths"] = merge_dir(SRC / "paths", "path")
    components = spec.setdefault("components", {})
    components["schemas"] = merge_dir(SRC / "schemas", "schema")
    return spec


def render(spec: dict) -> str:
    return json.dumps(spec, indent=2, sort_keys=True) + "\n"


def main() -> int:
    rendered = render(build())
    if "--check" in sys.argv:
        current = OUT.read_text() if OUT.exists() else ""
        if current != rendered:
            print("openapi.json is stale; run scripts/openapi-build.py", file=sys.stderr)
            return 1
        print("openapi.json matches its fragments")
        return 0
    OUT.write_text(rendered)
    spec = json.loads(rendered)
    operations = sum(
        1
        for item in spec["paths"].values()
        for method in item
        if not method.startswith("x-") and method != "parameters"
    )
    print(
        f"wrote {OUT.relative_to(ROOT)}: {len(spec['paths'])} paths, "
        f"{operations} operations, {len(spec['components']['schemas'])} schemas"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
