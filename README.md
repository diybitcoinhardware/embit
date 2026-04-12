# embit

A minimal bitcoin library for MicroPython and Python3 with a focus on embedded systems.

Should remain minimal to fit in a microcontroller. Also easy to audit.

Examples can be found in [`examples/`](./examples) folder.

Documentation: https://embit.rocks/

Support the project: `bc1qd4flfrxjctls9ya244u39hd67pcprhvka723gv`

# Requirements

## MicroPython

Requires a custom MicroPython build with extended [`hashlib`](https://github.com/diybitcoinhardware/f469-disco/tree/master/usermods/uhashlib) module and [`secp256k1`](https://github.com/diybitcoinhardware/secp256k1-embedded) bindings.

To install copy the content of `embit` folder to the board. To save some space you can remove files `embit/util/ctypes_secp256k1.py` and `embit/util/pyhashlib.py` - they are used only in Python3.

## Python 3

To install run `pip3 install embit`.

To install in development mode (editable) clone and run `pip3 install -e .` from the root folder.

PyPi installation includes prebuilt libraries for common platforms (win, macos, linux, raspi) - see [`src/embit/util/prebuilt/`](./src/embit/util/prebuilt/) folder. Library is built from [libsecp-zkp](https://github.com/ElementsProject/secp256k1-zkp) fork for Liquid support, but will work with pure [libsecp256k1](https://github.com/bitcoin-core/secp256k1) as well - just Liquid functionality doesn't work. If it fails to use the prebuilt or system library it will fallback to pure python implementation.

If you want to build the lib yourself, see: [Building secp256k1 for `embit`](/secp256k1/README.md).


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

Install [uv](https://docs.astral.sh/uv/), then sync dev dependencies (see `pyproject.toml`):

```bash
uv sync --dev
```

Run tooling via Poe tasks (same layout as the `embln` reference project):

```bash
uv run poe tests              # unit tests
uv run poe integration-tests # chain daemons + integration tests
uv run poe isort
uv run poe format
uv run poe pylint
```

## Building

Build the package (outputs to `dist/`):

```bash
uv build
```

Install from the built wheel:

```bash
pip install dist/embit-*.whl
```

The integration tests will compile `bitcoind` and `elementsd` in `/tmp`. You'll
need only install `berkeley-db@4` for `elementsd`.

## Pre-commit tools

Before commit your changes, perform some `pre-commit` check
(formatting, linting and test). If you do a commit without this check, you'll
need to wait a little (because it will run anyways).

First assert that you have `pre-commit` on your PATH (via `uv sync --dev`):

```sh
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

Then run:

```bash
# First run git add to update the checklist
git add <...>

# Pre-commit hooks
uv run pre-commit run --all-files

# The command above will run automatically when committing:
git commit -m <...> -S

# If you need to do a lot of rebases
# we recommend that you commit without verifying:
git commit -m <...> -S --no-verify
```

The commit commands will trigger some code quality checks:

- `isort` (sort python imports);
- `ruff format` (formatting);
- `pylint` (linter);
- `unit-tests` (`poe tests`);
- `integration-tests` (validate `embit` against `bitcoin-core` and
  `elements-core`);
- `conventional-commits` (validate commit messages).

## Tests

Unit tests:

```sh
uv run poe tests
```

Run tests with desktop python:

```sh
uv run poe integration-tests
```

Run tests with micropython:

```sh
cd tests
micropython ./run_tests.py
```
