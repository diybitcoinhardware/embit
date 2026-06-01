# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-06-01

### Added

- Add support for Taproot key spend signature in PSBT - `PSBT_IN_TAP_KEY_SIG`.
- Add miniscript boolean literal support for `0` and `1`.
- Add GitHub Actions CI for Python 3.10, 3.11, 3.12, and 3.13.
- Add release hardening workflows for package verification, dependency review,
  CodeQL scanning, release SBOM generation, and PyPI Trusted Publisher
  publishing.
- Add package inspection and artifact verification tools.
- Add `SECURITY.md`, `RELEASING.md`, `CODEOWNERS`, and package content policy
  documentation.
- Add hashed development constraints, `poetry.lock`, Ruff configuration, and
  updated development tooling.

### Changed

- Declare CPython support as Python 3.10+ in package metadata.
- Update secp256k1 ctypes backend discovery to prefer repo-local build outputs,
  then system `libsecp256k1`, then system `secp256k1`, then the legacy in-tree
  `src/embit/util/prebuilt` path.
- Use pure-Python fallbacks for optional secp256k1 modules when the loaded
  ctypes library does not expose the required symbols.
- Make BIP39 mnemonic validation stricter by rejecting leading spaces, trailing
  spaces, double spaces, newline-separated words, phrases shorter than 12 words,
  and phrases longer than 24 words.
- Enforce BIP39 entropy length of 16 to 32 bytes, in multiples of 4.
- Change several invalid input paths from `assert` checks to explicit
  `ValueError` or `embit`-specific exceptions.
- Use deterministic insertion order when collecting PSBT signing derivations and
  derived keypairs, making signing output reproducible.
- Update README and docs to describe pure Python artifacts, optional ctypes
  backend lookup, package inspection, security reporting, and release process.

### Fixed

- Fix descriptor parser offset handling for `tr(...)`, `sh(wsh(...))`,
  `wsh(...)`, `sh(wpkh(...))`, `wpkh(...)`, `pkh(...)`, and `sh(...)`.
- Fix descriptor and miniscript branch counting.
- Fix miniscript `t:` wrapper validation so it only accepts `V` fragments.
- Fix MicroPython test source path precedence so local sources are preferred.
- Fix the MicroPython-style unittest shim so `assertRaises(...) as exc` stores
  the caught exception.
- Fix CPython import discrimination so the repo-local `secp256k1/` build
  directory is not accidentally treated as an empty module.

### Removed

- Remove bundled native `libsecp256k1` binaries from package artifacts.
- Remove native libraries, `.pth` files, startup hook files, nested
  distributions, and unexpected metadata payloads from allowed package contents.

### Security

- Harden release artifacts to verify that no native binaries, install-time
  hooks, `.pth` files, nested distributions, or unexpected metadata payloads are
  shipped.
- Add dependency review gating for newly added dependencies.
- Add CodeQL scanning for Python and GitHub Actions workflows.
- Add release checksums, SBOM generation, and build provenance attestations.

### Compatibility

- CPython users now need Python 3.10 or newer.
- Users who need the ctypes backend must provide a compatible system
  `libsecp256k1`; otherwise `embit` falls back to pure Python where possible.
- Liquid and ZKP operations still require a secp256k1 library exposing the
  required ZKP symbols.
- Applications that accepted BIP39 phrases with extra whitespace or newline
  separators should normalize input before passing it to `embit`.
- Some invalid inputs now raise `ValueError` or `embit`-specific errors instead
  of `AssertionError`.
