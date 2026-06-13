# Building `libsecp256k1` for `embit` via Docker

`embit`'s ctypes backend wraps the `libsecp256k1` C library. The `embit` Python
package itself ships no compiled binaries -- you have to compile one for your
target platform.

This directory provides a self-contained Docker build environment so you
don't have to install cross-toolchains on your host. It is **not** invoked
automatically by `pip install embit`. Running it is a deliberate manual step
the first time you set up `embit` on a target platform (and again only when
you bump the `secp256k1-zkp` submodule).

See [Reproducibility properties](#reproducibility-properties) below for an
honest summary of what is and isn't pinned today.

## Supported targets

| Target    | Use case                                            |
| --------- | --------------------------------------------------- |
| `amd64`   | Native Linux x86_64 build (CI, desktops, servers)   |
| `armv6l`  | Raspberry Pi Zero                                   |
| `armv7l`  | Raspberry Pi 2/3, armhf devices                     |
| `aarch64` | arm64 Linux (Pi 4/5, embedded ARM)                  |
| `windows` | Cross-compile to `.dll` via mingw-w64               |

**macOS is intentionally not supported by this image.** Building natively on
a Mac (see below) is fast and only depends on Xcode Command Line Tools, which
Mac developers already have -- the isolation gain from a Linux container
isn't worth pulling in a third-party cross-toolchain.

## Quick start (Linux / Windows targets)

From the **embit repo root**:

```sh
# Build the image once.
docker build -t embit-libsecp docker/

# Pick a target. Output lands in secp256k1/build/.
# --user keeps files written into the bind-mounted workspace owned by your
# shell user (essential on Linux hosts; harmless on macOS).
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$PWD":/embit \
    -v "$PWD/.ccache":/ccache \
    embit-libsecp armv6l
```

The resulting file is `secp256k1/build/libsecp256k1_linux_armv6l.so`. The
container also automatically stages a copy at
`secp256k1/secp256k1-zkp/.libs/libsecp256k1.so` (the path the `embit` ctypes
loader checks first), so once the run completes `embit` will pick it up with
no further action. If you want a different deployment layout, copy the
artifact from `secp256k1/build/` to wherever you need it. See the universal
staging notes at
[`../secp256k1/README.md`](../secp256k1/README.md#make-embit-find-your-built-library-all-platforms),
including the macOS / Homebrew compatibility note.

Re-mount `$PWD/.ccache` on subsequent runs to get fast incremental rebuilds
across targets. The container also publishes a `ccache -s` summary at the end
of every build.

## macOS

macOS isn't built inside this container -- build natively on the Mac with
`cd secp256k1 && make`. See [`../secp256k1/README.md`](../secp256k1/README.md)
for the full instructions (including where to drop the resulting `.dylib` so
the loader finds it). CI exercises the macOS path on a `macos-latest` runner.

## What happens if `libsecp256k1` isn't found

`import embit` fails fast with
`embit.util.secp256k1.Libsecp256k1NotAvailable` (a subclass of
`ImportError`) and a message describing the search paths that were tried
and pointing at this directory for build instructions. It's a build/setup
error -- fix it by producing a `libsecp256k1` binary with this container
(or building natively per [`../secp256k1/README.md`](../secp256k1/README.md))
and staging it where the loader will find it.

## ccache (optional, local-dev only)

The image installs `ccache` and wires symlinks for every cross-toolchain so
the Makefile's `$(TOOLCHAIN_PREFIX)gcc` invocation transparently caches all
compiles. **CI doesn't use it** -- libsecp256k1 compiles in seconds, so the
overhead of plumbing a third-party action through CI isn't worth the tiny
speedup. Local devs iterating across multiple ARM targets in succession do
benefit; mount a host directory at `/ccache` to persist the cache between
container runs:

```sh
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$PWD":/embit \
    -v "$PWD/.ccache":/ccache \
    embit-libsecp armv6l
```

A `ccache -s` summary prints at the end of each build when `/ccache` is
mounted. Without the mount, ccache still runs inside the container but its
state is thrown away.

## Reproducibility properties

This build environment is fully pinned. A clean rebuild today vs. one a
year from now produces the same toolchain bits and the same libsecp256k1
artifact, provided the maintainer hasn't deliberately bumped one of the
inputs below.

**Pinned in this Dockerfile:**
- **`secp256k1-zkp` submodule** -- pinned by git SHA from the embit repo.
  Same code in → same C sources out.
- **Debian base image** -- pinned by digest
  (`debian:bookworm-slim@sha256:...`). Same digest in → same root
  filesystem at the `FROM` step.
- **apt package resolution** -- pinned via
  [`snapshot.debian.org`](https://snapshot.debian.org/). The
  `DEBIAN_SNAPSHOT` build arg (default in the Dockerfile) points apt at
  a frozen archive snapshot from a specific datetime, so every
  `apt-get install <name>` resolves to the same version on every run.

**Trade-off you should know about:** snapshot pinning means automatic
security updates from Debian are **not** picked up. Bumping the
`DEBIAN_SNAPSHOT` arg or the base-image digest is a deliberate maintainer
action. For a transient build container that processes a SHA-pinned
source tree and exits, this trade-off is the right call -- there's no
persistent attack surface that auto-updates would protect. But if the
project's threat model ever expands, it's worth revisiting.

**Not in scope of "reproducible" for this image:**
- **Native macOS builds** done outside this container (per
  [`../secp256k1/README.md`](../secp256k1/README.md)) depend on whatever
  Xcode CLT, host clang, and Homebrew packages are present. They're fine
  for personal use on a Mac; they're not a path to shipping the same
  binary to multiple consumers.
- **Container layer SHA stability.** Different Docker daemons / BuildKit
  versions can produce slightly different layer hashes for the same
  inputs (timestamp metadata, etc.). The *contents* are reproducible;
  the image's own SHA may vary. Distribute by content hash of the
  produced `.so` if you need to verify across consumers.

### Verifying your build matches CI

Every CI run publishes a `SHA256SUMS` file covering the five reproducible
targets (`amd64`, `armv6l`, `armv7l`, `aarch64`, `windows`). It's emitted
both as a workflow step-summary (visible at the top of the run page) and
as a downloadable workflow artifact named `libsecp256k1-sha256sums`. The
file's header records the embit commit, the `secp256k1-zkp` submodule
SHA, the Debian base image digest, and the `DEBIAN_SNAPSHOT` value used
for the build -- everything you need to confirm you're comparing apples
to apples.

To verify your own build matches CI:

```sh
# Every target uses an explicit cross-compiler inside the container, so the
# produced binary's architecture is fully decoupled from the host. No
# --platform flags needed. --user keeps files written into the
# bind-mounted workspace owned by your shell user. `all` is a pseudo-target
# that builds every supported arch in sequence.
docker build -t embit-libsecp docker/
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD":/embit embit-libsecp all

# Drop the SHA256SUMS from the CI artifact into secp256k1/build/ and
# verify:
cd secp256k1/build && sha256sum -c SHA256SUMS
```

If the hashes diverge, something in your build inputs differs from CI's
-- check the header in `SHA256SUMS` against your local `git submodule
status` and `docker/Dockerfile`.

### Bumping the snapshot

When you want to refresh:

```sh
# Pick a recent date from https://snapshot.debian.org/archive/debian/
# (any YYYYMMDDTHHMMSSZ that resolves -- apt follows the internal redirect).
docker build --build-arg DEBIAN_SNAPSHOT=20260901T000000Z -t embit-libsecp docker/
```

If a new version is going into the repo as the default, bump
`ARG DEBIAN_SNAPSHOT=...` in the [Dockerfile](./Dockerfile) directly.
Also bump the base image digest at the same time if you want Debian's
filesystem updates too:

```sh
docker pull debian:bookworm-slim
docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim
```

## Troubleshooting

- **`secp256k1-zkp submodule is not checked out`** -- run `git submodule
  update --init --recursive` in the embit repo first.
- **`macOS targets are not built inside this container`** -- by design.
  Build natively on the Mac with `cd secp256k1 && make`.
- **Slow incremental builds** -- make sure `$PWD/.ccache` is mounted at
  `/ccache` and writable. The first run primes the cache; subsequent runs
  should report a high hit rate from `ccache -s`.
