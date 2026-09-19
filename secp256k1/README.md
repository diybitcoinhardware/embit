# Building secp256k1 for `embit`

`embit` PyPI artifacts do not include prebuilt `libsecp256k1` binaries. On
CPython, `libsecp256k1` is required at runtime; build and install it locally
for your target platform. There is no pure-Python fallback.

If `libsecp256k1` is missing, `import embit` fails fast with
`embit.util.secp256k1.Libsecp256k1NotAvailable` (a subclass of
`ImportError`) whose message points back to this directory. This is a
build/setup error -- a deployment without `libsecp256k1` is broken and
should never reach an end user.

## Pick your build path

| Platform                              | Recommended path                                                       |
| ------------------------------------- | ---------------------------------------------------------------------- |
| macOS (Intel or Apple Silicon)        | **Native build** -- see below. Fast, no extra dependencies beyond Xcode CLT. |
| Linux x86_64 (development)            | Native build, or the Docker container in [`../docker/`](../docker/) for a self-contained build environment. |
| Linux ARM (Raspberry Pi, embedded)    | **Docker container** -- handles cross-compilation for `armv6l`, `armv7l`, `aarch64`. See [`../docker/README.md`](../docker/README.md). |
| Windows (.dll)                        | **Docker container** -- mingw cross-compile, see [`../docker/README.md`](../docker/README.md). |
| Microcontroller (STM32, ESP32, etc.)  | **Built separately in the firmware project's own build environment.** See "Microcontroller targets" below. |

## Clone `embit` recursively

We use the **libsecp256k1** fork --
[**secp256k1-zkp**](https://github.com/ElementsProject/secp256k1-zkp) -- because
Liquid support needs its extra crypto modules (ECDH, generator, pedersen,
rangeproof, surjectionproof, musig, schnorrsig).

Start by cloning `embit` with `--recursive`:

```sh
git clone --recursive https://github.com/diybitcoinhardware/embit.git
```

If you already cloned without `--recursive`, run:

```sh
git submodule update --init --recursive
```

If you see `make: *** No rule to make target 'build/secp256k1.o'`, the
submodule isn't initialized -- run the line above first.

## Native build (Linux, macOS)

This directory (`secp256k1/` in the `embit` root) ships a fully-configured
Makefile that handles `PLATFORM` and `ARCH` detection from `uname` for you.

```sh
cd secp256k1
make
```

Output lands at `secp256k1/build/libsecp256k1_<platform>_<arch>.{so,dylib}`.

### Clean

```sh
make clean
```

## Make `embit` find your built library (all platforms)

**This step applies to every build path -- native or Docker, Linux, macOS, or
Windows.** The Makefile writes its output to `secp256k1/build/`, but
`embit`'s ctypes loader searches a different set of paths in this order:

1. `secp256k1/secp256k1-zkp/.libs/libsecp256k1.{so,dylib,dll}` (autotools convention)
2. System loader (`ctypes.util.find_library("libsecp256k1")` then `"secp256k1"`)
3. `src/embit/util/prebuilt/` (compatibility-only path; no binaries shipped)

After building, copy or symlink the artifact into the `.libs/` path so the
loader finds your zkp build first. (The Docker container's `build.sh`
wrapper does this for you automatically. Native `make` does not -- you'll
need to run the `cp` yourself.) Examples (substitute the actual filename for
your platform):

```sh
mkdir -p secp256k1/secp256k1-zkp/.libs

# macOS Apple Silicon
cp secp256k1/build/libsecp256k1_darwin_arm64.dylib \
   secp256k1/secp256k1-zkp/.libs/libsecp256k1.dylib

# Linux x86_64
cp secp256k1/build/libsecp256k1_linux_x86_64.so \
   secp256k1/secp256k1-zkp/.libs/libsecp256k1.so

# Raspberry Pi Zero (after a Docker cross-compile)
cp secp256k1/build/libsecp256k1_linux_armv6l.so \
   secp256k1/secp256k1-zkp/.libs/libsecp256k1.so
```

Alternatively, install the artifact to a standard system library location
(e.g. `/usr/local/lib` on Unix-like systems with `ldconfig`) so the system
loader resolves it. Either approach works.

### ⚠️ macOS / Homebrew compatibility

If you have Homebrew's `libsecp256k1` installed (`brew install secp256k1`),
you **must** do the `.libs/` copy step above. Homebrew ships upstream
`bitcoin-core/secp256k1`, not the `secp256k1-zkp` fork that `embit` requires:

- Upstream is missing some legacy symbol aliases that `embit`'s ctypes
  wrapper binds (e.g. `secp256k1_ec_privkey_negate`, which was renamed to
  `secp256k1_ec_seckey_negate`).
- Upstream is missing all of the ZKP/Liquid extras (ECDH, generator,
  pedersen, rangeproof, surjectionproof, musig).

If the loader picks up Homebrew's version before your zkp build, `embit`
will fail to initialize with messages like:

```
dlsym(...): symbol not found  ->  secp256k1_ec_privkey_negate
```

Staging your build at `secp256k1/secp256k1-zkp/.libs/libsecp256k1.dylib`
puts it ahead of the system loader and avoids the conflict.

## Cross-compilation

For ARM (Raspberry Pi, embedded) and Windows targets, use the Docker
container at [`../docker/README.md`](../docker/README.md). It bundles all
required cross-toolchains and exposes a single-command wrapper
(`build.sh armv6l`, `build.sh windows`, etc.). See its
"Reproducibility properties" section for what's pinned.

## Microcontroller targets

Microcontroller targets (STM32, ESP32-S3, ESP32-P4, and similar embedded
MicroPython platforms) are out of scope for both the native `make` flow here
and the Docker container in [`../docker/`](../docker/). They don't fit
either flow because:

- **They use project-specific build systems.** Each firmware project pins
  its own toolchain and build infrastructure (e.g. ARM GCC + per-board
  linker scripts for STM32, ESP-IDF + CMake for ESP32). Neither the
  `secp256k1/Makefile` nor the cross-compile Docker image knows how to
  drive those.
- **They consume `libsecp256k1` differently.** Embedded MicroPython doesn't
  load `libsecp256k1` via `ctypes`; the `secp256k1` native module is
  statically linked into the firmware image, so there is no standalone
  `.so` for `embit` to discover at runtime.

For those targets, `libsecp256k1` is compiled as part of the firmware
project's own build, using whatever toolchain and configuration that project
pins. The resulting binding ships inside the firmware -- not through any
path documented here.
