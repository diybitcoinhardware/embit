# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add PSBT version 2 (BIP 370) support to `PSBT` and `PSBTView`: parsing,
  validation and serialization of the v2 global, input and output fields,
  unsigned transaction reconstruction, and `PSBT_GLOBAL_TX_MODIFIABLE`
  updates on signing.

### Changed

- `PSBTView.locktime` now has the same meaning as `PSBT.locktime` (the raw
  fallback field for PSBTv2); the derived transaction locktime is
  `PSBTView.determine_locktime()`.
- `PSBTView.view()` walks every input and output map once and rejects a PSBT
  with trailing data or fewer maps than the global counts declare.
- `compact.read_from` rejects non-canonical and truncated compact-size
  encodings, as Bitcoin Core does.
- `PSBTView` hashes prevouts, sequences and outputs in a single pass and
  caches the per-input utxo data used by taproot sighashes.

### Fixed

- Validate PSBTv2 count fields canonically and raise `PSBTError` instead of
  `RuntimeError`/`ValueError` on malformed values in both parse paths.
- `PSBTView` matched PSBTv2 prevout and output fields by key prefix, so a
  keyed or duplicated field could feed a wrong value into the sighash.
- Every malformed PSBT now raises `PSBTError` from both `PSBT` and
  `PSBTView`, including truncated input, corrupted nested transactions,
  keys and scripts, and out-of-range values on serialization.
- `PSBT_IN_NON_WITNESS_UTXO` is held to its declared length.
- `PSET` signed PSETv2 with the fallback locktime instead of the BIP-370
  derived one, and rewrote a zero input sequence to `0xffffffff`.
- `PSBT` and `PSBTView` now write the PSBTv2 global map in the same order and
  both store `PSBT_IN_TAP_KEY_SIG` for taproot key-path signatures.
- `InputScope`/`OutputScope` accept PSBTv2 fields through the `unknown`
  constructor argument with `version=2`.
- Signing an input without a utxo raises `PSBTError` instead of
  `AttributeError`.
- Taproot sighashes with `ANYONECANPAY` hashed the whole serialized input
  instead of the outpoint, and `SIGHASH_SINGLE` hashed the output instead of
  its SHA256, in both `Transaction` and `PSBTView` (#65).
- `PSBT.parse` rejected a PSBTv0 whose unsigned transaction has no inputs,
  taking the zero input count for a segwit marker (#117).
- `PSET` v2 outputs without an asset or asset commitment are rejected at parse
  time instead of failing with `TypeError` when hashed.

## [0.8.2] - 2026-08-08

### Changed

- Align PSBT version parsing and serialization with BIP 174 and BIP 370 across
  `PSBT` and `PSBTView`.

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
