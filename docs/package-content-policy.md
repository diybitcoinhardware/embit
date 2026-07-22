# Package Content Policy

This project publishes source-only Python artifacts.

## Allowed in published artifacts

- Python source files required at runtime (`src/embit/**/*.py`)
- Build metadata and license files

## Forbidden in published artifacts

- `.pth` files
- `sitecustomize.py` and `usercustomize.py`
- Bundled native binaries (`*.so`, `*.dylib`, `*.dll`) in any package path
- Bundled executable binaries beyond the reviewed native library suffixes above
- Nested distributions (`*.whl`, `*.tar.gz`, `*.egg`) embedded inside sdist/wheel payloads
- Nested package metadata payloads (`*.egg-info`, `*.dist-info`) from other distributions
- Prebuilt native artifacts under `src/embit/util/prebuilt/`
- Top-level executable scripts unless intentionally declared in packaging metadata and reviewed
- Install-time network access
- Install-time execution hooks, including custom setup/install commands or hidden startup injection paths
- Release-time code generation from the network

## Packaging controls

- `MANIFEST.in` is the source of truth for sdist include/prune behavior.
- Setuptools package data must not include native artifacts.
- `setup.py` must remain declarative. It must not define custom command classes,
  install hooks, or other build/install execution paths.
- Artifact verification must inspect built sdists and wheels, not only the
  source tree, and confirm mechanically checkable forbidden payloads are absent
  before release.
- Non-mechanical policy items must be covered by release-sensitive file review.
