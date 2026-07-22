from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--output", default="release-metadata/embit-sbom.cdx.json")
    return parser.parse_args()


def latest_file(dist_dir: Path, pattern: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if not matches:
        raise SystemExit(f"no artifact found for pattern {pattern!r} in {dist_dir}")
    return matches[-1]


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheel_metadata(wheel: Path) -> dict[str, list[str] | str]:
    with zipfile.ZipFile(wheel) as zf:
        metadata_name = next(
            name for name in zf.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = zf.read(metadata_name).decode("utf-8")

    fields: dict[str, list[str] | str] = {"requires_dist": []}
    for line in metadata.splitlines():
        if line.startswith("Summary: "):
            fields["summary"] = line.removeprefix("Summary: ")
        elif line.startswith("License: "):
            fields["license"] = line.removeprefix("License: ")
        elif line.startswith("Requires-Dist: "):
            if "extra ==" not in line:
                raise SystemExit(
                    f"wheel contains unexpected runtime dependency metadata: {line}"
                )
            casted = fields["requires_dist"]
            if not isinstance(casted, list):
                raise SystemExit("internal error: requires_dist must be a list")
            casted.append(line.removeprefix("Requires-Dist: "))
    return fields


def external_reference(path: Path) -> dict:
    digest = file_hash(path)
    return {
        "type": "distribution",
        "url": f"file:dist/{path.name}",
        "comment": f"SHA256: {digest}",
        "hashes": [{"alg": "SHA-256", "content": digest}],
    }


def read_pyproject() -> dict:
    with Path("pyproject.toml").open("rb") as f:
        return tomllib.load(f)


def build_sbom(*, wheel: Path, sdist: Path) -> dict:
    pyproject = read_pyproject()
    project = pyproject["project"]
    metadata = wheel_metadata(wheel)
    name = project["name"]
    version = project["version"]
    package_ref = f"pkg:pypi/{name}@{version}"
    serial_source = f"{package_ref}:{file_hash(wheel)}:{file_hash(sdist)}"
    serial_number = f"urn:uuid:{uuid5(NAMESPACE_URL, serial_source)}"

    component = {
        "type": "library",
        "bom-ref": package_ref,
        "name": name,
        "version": version,
        "description": metadata.get("summary", project.get("description", "")),
        "purl": package_ref,
        "hashes": [
            {
                "alg": "SHA-256",
                "content": hashlib.sha256(
                    f"{file_hash(wheel)}\n{file_hash(sdist)}".encode("utf-8")
                ).hexdigest(),
            }
        ],
        "externalReferences": [
            external_reference(wheel),
            external_reference(sdist),
            *[
                {"type": "website", "url": url, "comment": label}
                for label, url in sorted(project.get("urls", {}).items())
            ],
        ],
        "properties": [
            {
                "name": "embit:requires-python",
                "value": project["requires-python"],
            },
            {
                "name": "embit:runtime-dependencies",
                "value": "none",
            },
        ],
    }

    license_text = metadata.get("license")
    if isinstance(license_text, str) and license_text:
        component["licenses"] = [{"license": {"name": license_text}}]

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "tools/generate_release_sbom.py",
                    }
                ]
            },
            "component": component,
        },
        "components": [],
        "dependencies": [{"ref": package_ref, "dependsOn": []}],
    }


def write_sbom(path: Path, sbom: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, sort_keys=True)
        f.write("\n")


def main() -> None:
    args = parse_args()
    dist_dir = Path(args.dist_dir)
    wheel = latest_file(dist_dir, "embit-*.whl")
    sdist = latest_file(dist_dir, "embit-*.tar.gz")
    output = Path(args.output)

    write_sbom(output, build_sbom(wheel=wheel, sdist=sdist))
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
