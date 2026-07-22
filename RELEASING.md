# Releasing `embit`

This project publishes from GitHub Actions only. Do not run `twine upload` from local machines.

## Release Invariants

- Release tags must reference commits already merged into the protected default branch.
- Artifacts must be built once in the unprivileged build job, then reused in publish.
- Publishing must use PyPI Trusted Publisher through the protected `pypi` environment.
- Release artifacts must remain pure Python (no bundled native libraries).

## Pre-Publish Checklist (Before Approving `pypi`)

- Confirm the tag resolves to the intended commit already merged on the protected default branch.
- Confirm CI passed tests, package-content checks, and artifact inspection for that exact commit.
- Compare artifact filenames and SHA256 values against CI-generated checksums.
- Confirm the build job generated `release-metadata/embit-sbom.cdx.json`.
- Extract the release bundle into a clean temporary directory and confirm it contains only the expected release files:
  `dist/*.tar.gz`, `dist/*.whl`, `release-metadata/SHA256SUMS`,
  `release-metadata/embit-sbom.cdx.json`, and
  `release-metadata/release-package-inspection.md`.
- Run installed-artifact smoke imports from outside the repository checkout so repo-local paths cannot affect backend selection.
- Confirm the publish-only job downloads previously built artifacts and cannot rebuild.
- Confirm release notes match the tagged changes and version.

## Post-Publish Checklist

- Compare PyPI artifact SHA256 values against CI-generated checksums.
- Compare GitHub Release artifact SHA256 values against CI-generated checksums.
- Confirm PyPI and GitHub Release artifacts correspond to the intended tag and commit.
- Confirm published artifact set matches workflow output exactly with no unexpected files.
- Confirm artifact attestations were generated and attached for the release artifacts.
- Confirm the SBOM in the release bundle names the released version and built artifacts.
- Verify PyPI metadata (`Name`, `Version`, `Requires-Python`, dependencies/extras, project URLs) matches repository metadata.
- Confirm the release workflow did not restore reusable caches from other workflows.
- When practical, perform approval and verification from a fresh browser session or separate device from day-to-day development.

## Rollback Path (If Any Verification Fails)

1. Yank the affected release on PyPI immediately.
2. Pause new releases and disable release workflow dispatch until investigation starts.
3. Revoke or rotate any possibly exposed credentials and review GitHub/PyPI security events.
4. If compromise is plausible, revoke PyPI Trusted Publisher until workflow integrity is re-established.
5. Publish an incident note identifying affected versions and required user action.

## Prohibited Release Paths

- No `twine upload` from laptops.
- No local build-push-distribute flow for releases.
- No emergency direct uploads.
- No release from a dirty local checkout.
- No publishing from forks.
- No approval of `pypi` before build-and-verify outputs are reviewed.
