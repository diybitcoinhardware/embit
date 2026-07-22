from __future__ import annotations

import argparse
import email
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


FORBIDDEN_SUFFIXES = (
    ".pth",
    "sitecustomize.py",
    "usercustomize.py",
    ".so",
    ".dylib",
    ".dll",
    ".tar.gz",
    ".whl",
    ".egg",
)

FORBIDDEN_SUBSTRINGS = (
    "util/prebuilt/",
)


@dataclass(frozen=True)
class ArtifactMetadata:
    headers: email.message.Message
    entry_points: set[str]
    label: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument(
        "--inspection-log",
        default=None,
        help="Optional path to store a package inspect style report.",
    )
    return parser.parse_args()


def latest_file(dist_dir: Path, pattern: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if not matches:
        raise SystemExit(f"no artifact found for pattern {pattern!r} in {dist_dir}")
    return matches[-1]


def read_pyproject() -> dict:
    with Path("pyproject.toml").open("rb") as f:
        return tomllib.load(f)


def parse_requirement(requirement: str) -> Requirement:
    try:
        return Requirement(requirement)
    except InvalidRequirement as exc:
        raise SystemExit(f"could not parse requirement {requirement!r}: {exc}") from exc


def normalized_requirement(requirement: str | Requirement) -> str:
    parsed = (
        parse_requirement(requirement)
        if isinstance(requirement, str)
        else requirement
    )
    normalized = canonicalize_name(parsed.name)
    if parsed.extras:
        extras = ",".join(sorted(canonicalize_name(extra) for extra in parsed.extras))
        normalized += f"[{extras}]"
    if parsed.url:
        normalized += f" @ {parsed.url}"
    normalized += str(parsed.specifier)
    if parsed.marker is not None:
        normalized += f"; {parsed.marker}"
    return normalized


def requirement_with_extra(requirement: str, extra: str) -> Requirement:
    parsed = parse_requirement(requirement)
    extra_marker = f'extra == "{extra}"'
    if parsed.marker is None:
        parsed.marker = Marker(extra_marker)
    else:
        parsed.marker = Marker(f"({parsed.marker}) and {extra_marker}")
    return parsed


def requirement_has_expected_extra_marker(requirement: str, extras: set[str]) -> bool:
    marker = parse_requirement(requirement).marker
    if marker is None:
        return False
    marker_text = str(marker)
    return any(f'extra == "{extra}"' in marker_text for extra in extras)


def expected_metadata_from_pyproject(pyproject: dict) -> dict:
    project = pyproject["project"]
    optional_dependencies = {
        canonicalize_name(extra): requirements
        for extra, requirements in project.get("optional-dependencies", {}).items()
    }
    return {
        "name": project["name"],
        "version": project["version"],
        "requires_python": project["requires-python"],
        "classifiers": set(project.get("classifiers", [])),
        "project_urls": {
            f"{key}, {value}" for key, value in project.get("urls", {}).items()
        },
        "extras": set(optional_dependencies),
        "optional_requirements": {
            normalized_requirement(requirement_with_extra(requirement, extra))
            for extra, requirements in optional_dependencies.items()
            for requirement in requirements
        },
    }


def parse_entry_points(contents: str) -> set[str]:
    entries: set[str] = set()
    section: str | None = None
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section is not None:
            entries.add(f"{section}:{line}")
    return entries


def inspect_sdist(sdist: Path, expected: dict) -> ArtifactMetadata:
    with tarfile.open(sdist, "r:gz") as tf:
        members = [member.name for member in tf.getmembers() if member.isfile()]
        root_prefix = Path(members[0]).parts[0]
        pkg_info_member = tf.extractfile(f"{root_prefix}/PKG-INFO")
        if pkg_info_member is None:
            raise SystemExit("sdist PKG-INFO missing")
        metadata = email.message_from_bytes(pkg_info_member.read())
        try:
            entry_points_member = tf.extractfile(
                f"{root_prefix}/src/{expected['name']}.egg-info/entry_points.txt"
            )
        except KeyError:
            entry_points_member = None
        entry_points = (
            parse_entry_points(entry_points_member.read().decode())
            if entry_points_member is not None
            else set()
        )
    verify_artifact_members(
        label="sdist",
        members=members,
        allowed_dist_info_prefix=None,
        allowed_egg_info_prefix=f"{root_prefix}/src/{expected['name']}.egg-info/",
    )
    verify_metadata(
        metadata=metadata,
        entry_points=entry_points,
        expected=expected,
        label="sdist",
        require_dependency_metadata=False,
    )
    return ArtifactMetadata(headers=metadata, entry_points=entry_points, label="sdist")


def inspect_wheel(wheel: Path, expected: dict) -> ArtifactMetadata:
    with zipfile.ZipFile(wheel) as zf:
        members = zf.namelist()
        metadata_name = next(
            name for name in members if name.endswith(".dist-info/METADATA")
        )
        metadata = email.message_from_bytes(zf.read(metadata_name))
        entry_points_name = next(
            (name for name in members if name.endswith(".dist-info/entry_points.txt")),
            None,
        )
        entry_points = (
            parse_entry_points(zf.read(entry_points_name).decode())
            if entry_points_name is not None
            else set()
        )
    verify_artifact_members(
        label="wheel",
        members=members,
        allowed_dist_info_prefix=(
            f"{expected['name'].replace('-', '_')}-{expected['version']}.dist-info/"
        ),
        allowed_egg_info_prefix=None,
    )
    verify_metadata(
        metadata=metadata,
        entry_points=entry_points,
        expected=expected,
        label="wheel",
        require_dependency_metadata=True,
    )
    return ArtifactMetadata(headers=metadata, entry_points=entry_points, label="wheel")


def verify_artifact_members(
    *,
    label: str,
    members: Iterable[str],
    allowed_dist_info_prefix: str | None,
    allowed_egg_info_prefix: str | None,
) -> None:
    for member in members:
        normalized = member.lstrip("./")
        if any(normalized.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            raise SystemExit(f"{label} contains forbidden file: {member}")
        for substring in FORBIDDEN_SUBSTRINGS:
            if substring in normalized:
                raise SystemExit(f"{label} contains forbidden path: {member}")
        if ".dist-info/" in normalized and (
            allowed_dist_info_prefix is None
            or not normalized.startswith(allowed_dist_info_prefix)
        ):
            raise SystemExit(f"{label} contains unexpected dist-info payload: {member}")
        if ".egg-info/" in normalized and (
            allowed_egg_info_prefix is None
            or not normalized.startswith(allowed_egg_info_prefix)
        ):
            raise SystemExit(f"{label} contains unexpected egg-info payload: {member}")
        if normalized.endswith("/"):
            continue
        if normalized.startswith("embit-") and "/scripts/" in normalized:
            raise SystemExit(f"{label} contains unexpected script payload: {member}")


def verify_metadata(
    *,
    metadata: email.message.Message,
    entry_points: set[str],
    expected: dict,
    label: str,
    require_dependency_metadata: bool,
) -> None:
    if metadata.get("Name") != expected["name"]:
        raise SystemExit(f"{label} name mismatch: {metadata.get('Name')!r}")
    if metadata.get("Version") != expected["version"]:
        raise SystemExit(f"{label} version mismatch: {metadata.get('Version')!r}")
    if metadata.get("Requires-Python") != expected["requires_python"]:
        raise SystemExit(
            f"{label} requires-python mismatch: {metadata.get('Requires-Python')!r}"
        )
    classifiers = set(metadata.get_all("Classifier", []))
    if classifiers != expected["classifiers"]:
        raise SystemExit(
            f"{label} classifiers mismatch: "
            f"{sorted(classifiers)!r} != {sorted(expected['classifiers'])!r}"
        )

    project_urls = set(metadata.get_all("Project-URL", []))
    if project_urls != expected["project_urls"]:
        raise SystemExit(
            f"{label} project URLs mismatch: {sorted(project_urls)!r} != "
            f"{sorted(expected['project_urls'])!r}"
        )

    extras = set(metadata.get_all("Provides-Extra", []))
    if require_dependency_metadata and extras != expected["extras"]:
        raise SystemExit(
            f"{label} extras mismatch: "
            f"{sorted(extras)!r} != {sorted(expected['extras'])!r}"
        )
    if not require_dependency_metadata and extras and extras != expected["extras"]:
        raise SystemExit(
            f"{label} extras mismatch: "
            f"{sorted(extras)!r} != {sorted(expected['extras'])!r}"
        )

    requirement_headers = metadata.get_all("Requires-Dist", [])
    requirements = {normalized_requirement(req) for req in requirement_headers}
    if (
        require_dependency_metadata
        and requirements != expected["optional_requirements"]
    ):
        raise SystemExit(
            f"{label} dependency metadata mismatch: {sorted(requirements)!r} != "
            f"{sorted(expected['optional_requirements'])!r}"
        )
    if (
        not require_dependency_metadata
        and requirements
        and requirements != expected["optional_requirements"]
    ):
        raise SystemExit(
            f"{label} dependency metadata mismatch: {sorted(requirements)!r} != "
            f"{sorted(expected['optional_requirements'])!r}"
        )
    for requirement in requirement_headers:
        if not requirement_has_expected_extra_marker(requirement, expected["extras"]):
            raise SystemExit(
                f"{label} has unexpected non-extra dependency: {requirement}"
            )

    if entry_points:
        raise SystemExit(
            f"{label} contains unexpected entry points: {sorted(entry_points)!r}"
        )


def write_inspection_log(log_path: Path, *, wheel: Path, sdist: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        f.write(render_inspection_report(wheel=wheel, sdist=sdist))


def render_inspection_report(*, wheel: Path, sdist: Path) -> str:
    sections: list[str] = ['# PACKAGE CONTENT OF "embit"\n']

    with zipfile.ZipFile(wheel) as zf:
        metadata_name = next(
            name for name in zf.namelist() if name.endswith(".dist-info/METADATA")
        )
        data = zf.read(metadata_name).decode()
        sections.append("\n## METADATA\n")
        for line in data.splitlines():
            if line.startswith(
                (
                    "Name:",
                    "Version:",
                    "Requires-Python:",
                    "Classifier:",
                    "Project-URL:",
                    "Requires-Dist:",
                    "Provides-Extra:",
                )
            ):
                sections.append(f"{line}  \n")

    sections.append("\n## SDIST FILE LIST\n")
    with tarfile.open(sdist, "r:gz") as tf:
        for member in tf.getmembers():
            sections.append(f"{member.name}  \n")

    sections.append("\n## WHEEL FILE LIST\n")
    with zipfile.ZipFile(wheel) as zf:
        for name in zf.namelist():
            sections.append(f"{name}  \n")

    return "".join(sections)


def main() -> None:
    args = parse_args()
    dist_dir = Path(args.dist_dir)
    pyproject = read_pyproject()
    expected = expected_metadata_from_pyproject(pyproject)

    wheel = latest_file(dist_dir, "embit-*.whl")
    sdist = latest_file(dist_dir, "embit-*.tar.gz")

    inspect_wheel(wheel, expected)
    inspect_sdist(sdist, expected)

    if args.inspection_log is not None:
        write_inspection_log(Path(args.inspection_log), wheel=wheel, sdist=sdist)

    print(f"verified {wheel.name} and {sdist.name}")


if __name__ == "__main__":
    main()
