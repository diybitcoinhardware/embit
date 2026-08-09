# embit

A minimal bitcoin library for MicroPython and Python 3.10+ with a focus on embedded systems.

Should remain minimal to fit in a microcontroller. Also easy to audit.

Examples can be found in [`examples/`](./examples) folder.

Documentation: https://embit.rocks/

Support the project: `bc1qd4flfrxjctls9ya244u39hd67pcprhvka723gv`

# Requirements

## MicroPython

Requires a custom MicroPython build with extended [`hashlib`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/uhashlib) module and [`secp256k1`](https://github.com/diybitcoinhardware/secp256k1-embedded) bindings.

To install copy the content of `embit` folder to the board. To save some space you can remove files `embit/util/ctypes_secp256k1.py` and `embit/util/pyhashlib.py` - they are used only in CPython.

## Python 3

To install run `pip3 install embit`.

To install in development mode (editable) clone and run `pip3 install -e .` from the root folder.

PyPI artifacts are pure Python and do not bundle prebuilt `libsecp256k1` binaries.
On CPython, `libsecp256k1` is a hard runtime requirement -- there is no pure-Python
fallback. If the library is missing, `import embit` fails fast with
`embit.util.secp256k1.Libsecp256k1NotAvailable` (a subclass of `ImportError`)
whose message describes how to build the library. This is a build/setup
error, not a runtime condition to be detected later.

ctypes library discovery order is:

1. `secp256k1/secp256k1-zkp/.libs` (repo-local build outputs)
2. system loader (`libsecp256k1`)
3. system loader (`secp256k1`)
4. `src/embit/util/prebuilt/*` (compatibility-only path; no binaries are shipped in package artifacts)

Build options:
- **Native build on Linux or macOS** -- the existing Makefile in
  [`secp256k1/`](/secp256k1/README.md) handles host platform/arch detection.
  Fast and dependency-light; recommended for macOS and Linux x86_64
  development.
- **Docker container** -- the self-contained cross-compile environment in
  [`docker/`](./docker/README.md) covers ARMv6L (Pi Zero), ARMv7, aarch64,
  and Windows. Recommended for any embedded ARM target or Windows build.
  See the Docker README for an honest accounting of what is and isn't
  reproducible.


## Using non-English BIP39 wordlists
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md) defines wordlists for:
* English
* Japanese
* Korean
* Spanish
* Chinese (Simplified)
* Chinese (Traditional)
* French
* Italian
* Czech
* Portuguese

`embit` assumes English and does not include the other wordlists in order to keep this as slim as possible.

However, you can override this default by providing an alternate wordlist to any of the mnemonic-handling methods:
```
spanish_wordlist = [
    "ábaco",
    "abdomen",
    "abeja",
    "abierto",
    "abogado",
    "abono",
    "aborto",
    "abrazo",
    "abrir",
    "abuelo",
    ...
]

mnemonic_is_valid(mnemonic, wordlist=spanish_wordlist)
mnemonic_to_seed(mnemonic, wordlist=spanish_wordlist)
mnemonic_to_bytes(mnemonic, wordlist=spanish_wordlist)
mnemonic_from_bytes(bytes_data, wordlist=spanish_wordlist)
```


# Development

Install in developer mode with dev dependencies:

```sh
pip install -e .[dev]
```

Install pre-commit hook:

```sh
pre-commit install
```

Run tests with desktop python:

```sh
pytest
```

Run tests with micropython:

```sh
cd tests
micropython ./run_tests.py
```

Inspect built package contents (latest wheel and sdist from `dist/`):

```sh
python tools/package_inspect.py
```

This helper prints selected package metadata (`Name`, `Version`, `Requires-Python`,
dependencies/extras, project URLs) and full file lists for both artifacts.
