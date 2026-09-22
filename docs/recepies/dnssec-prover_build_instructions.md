# Building DNSSEC Prover Binaries

This document explains how the DNSSEC prover binaries in `src/embit/util/prebuilt/` were created and how to reproduce them.

## Overview

The DNSSEC prover binaries provide offline DNSSEC validation capabilities for BIP-353 support in `embit`. They are generated from [@TheBlueMatt's dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover) Rust tool using uniffi for cross-compilation.

## Binary Files

The following prebuilt binaries are included:

| Platform | Architecture | File |
|----------|--------------|------|
| macOS | ARM64 | `libuniffi_dnssec_prover_darwin_arm64.dylib` |
| macOS | x86_64 | `libuniffi_dnssec_prover_darwin_x86_64.dylib` |
| Linux | ARM64 | `libuniffi_dnssec_prover_linux_aarch64.so` |
| Linux | ARMv6 | `libuniffi_dnssec_prover_linux_armv6l.so` |
| Linux | ARMv7 | `libuniffi_dnssec_prover_linux_armv7l.so` |
| Linux | x86_64 | `libuniffi_dnssec_prover_linux_x86_64.so` |
| Windows | AMD64 | `libuniffi_dnssec_prover_windows_amd64.dll` |

### Prerequisites

- **Docker**: Install Docker Desktop or Docker Engine
- **Python**: Version 3.10 or 3.12

## Docker Build Approach

Instead of cross-compilation, we use Docker to build natively for most platforms. This approach is more reliable and avoids linker issues.

## Build Process

### 1. Build for macOS ARM64 (Apple Silicon)

```bash
# Not available for cross-compilation. Must be built from macOS ARM64
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib
```

### 2. Build for macOS x86_64 (Intel)

```bash
# Not available for cross-compilation. Must be built from macOS x86_64
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
```

### 3. Build for Linux ARM64

```bash
# Build using Docker with ARM64 Linux
docker run --rm --platform linux/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-unknown-linux-gnu &&
cargo build --release --target aarch64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_aarch64.so
"
```

### 4. Build for Linux ARMv6

```bash
# Build using Docker with ARMv6 Linux (use linux/arm for compatibility)
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add arm-unknown-linux-gnueabihf &&
cargo build --release --target arm-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/arm-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv6l.so
"
```

### 5. Build for Linux ARMv7

```bash
# Build using Docker with ARMv7 Linux (use linux/arm for compatibility)
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add armv7-unknown-linux-gnueabihf &&
cargo build --release --target armv7-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/armv7-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv7l.so
"
```

### 6. Build for Linux x86_64

```bash
# Build using Docker with x86_64 Linux
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-unknown-linux-gnu &&
cargo build --release --target x86_64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_x86_64.so
"
```

### 7. Build for Windows AMD64

```bash
# Build using Docker with Windows container
# rust:latest is not published as a Windows container, so we compile from an x86_64 Linux container
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
apt-get update &&
apt-get install -y mingw-w64 &&
rustup target add x86_64-pc-windows-gnu &&
cargo build --release --target x86_64-pc-windows-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-gnu/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"
```

## Complete Build Script

Here's a script that builds everything using Docker:

```bash
# Create complete build script (remove macOS builds if running from Linux)
cat > build-all-platforms.sh << 'EOF'
#!/bin/bash
set -e

echo "Building DNSSEC Prover for all platforms using Docker..."

mkdir -p dist

# macOS builds 
echo "Building macOS ARM64..."
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib

echo "Building macOS x86_64..."
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib

# Linux builds (Docker)
echo "Building Linux ARM64..."
docker run --rm --platform linux/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-unknown-linux-gnu &&
cargo build --release --target aarch64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_aarch64.so
"

echo "Building Linux ARMv6..."
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add arm-unknown-linux-gnueabihf &&
cargo build --release --target arm-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/arm-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv6l.so
"

echo "Building Linux ARMv7..."
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add armv7-unknown-linux-gnueabihf &&
cargo build --release --target armv7-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/armv7-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv7l.so
"

echo "Building Linux x86_64..."
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-unknown-linux-gnu &&
cargo build --release --target x86_64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_x86_64.so
"

# Windows build (Docker)
echo "Building Windows AMD64..."
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
apt-get update &&
apt-get install -y mingw-w64 &&
rustup target add x86_64-pc-windows-gnu &&
cargo build --release --target x86_64-pc-windows-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-gnu/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"

shasum -a 256 dist/libuniffi_dnssec_prover_*
EOF

# Make executable and run
chmod +x build-all-platforms.sh
./build-all-platforms.sh
```

### Expected hash output:
```bash
6ef0d1d762a0171b0ff2d5b09730096667be252ebf9cb7aafe5a09de4a5e839b  dist/libuniffi_dnssec_prover_darwin_arm64.dylib
35128508261ac7e2185fdeb7f8af0f811e8924cf4237e5d717bd9b7aa1be6f85  dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
678c0e0566b361099b800bc457b74f041afb4b88aed8eee8681b21ffccf5ce0d  dist/libuniffi_dnssec_prover_linux_aarch64.so
9a7762204ca92e34b64c97dfbb52a3f25210e00c950409288d91e97feb9d5e45  dist/libuniffi_dnssec_prover_linux_armv6l.so
88e8d790bd21f686b7828798bcd0fb99adb9d1513be774f4a7f0cde462c77ff4  dist/libuniffi_dnssec_prover_linux_armv7l.so
66fab93c1ab388f4e09775e9be6cc70a9f8fe0778924719ea8758dafdfd7087a  dist/libuniffi_dnssec_prover_linux_x86_64.so
4d13fe7e0ee376105098f2132e58fa90bb892a9154212c86236405eb3d14a612  dist/libuniffi_dnssec_prover_windows_amd64.dll
```

The binaries can then be moved to the `src/embit/util/prebuilt/` directory.

## Generate Python Bindings

After building all platforms, generate Python bindings:

```bash
cd uniffi
cargo run --bin uniffi-bindgen generate \
  --library ../dist/libuniffi_dnssec_prover_linux_x86_64.so \
  --out-dir ../python-bindings \
  --language python
```

## Required Patch for dnssec_prover.py

The generated Python bindings need a patch to fix library loading and adapt them to the same approach used in `embit` for secp256k1 bindings. 
Apply this patch to `python-bindings/dnssec_prover.py`:

```diff
--- a/python-bindings/dnssec_prover.py
+++ b/python-bindings/dnssec_prover.py
@@ -429,27 +429,50 @@
 def _uniffi_load_indirect():
     """
     This is how we find and load the dynamic library provided by the component.
-    For now we just look it up by name.
+    We use the same pattern as ctypes_secp256k1.py for consistency.
     """
-    if sys.platform == "darwin":
-        libname = "lib{}.dylib"
-    elif sys.platform.startswith("win"):
-        # As of python3.8, ctypes does not seem to search $PATH when loading DLLs.
-        # We could use `os.add_dll_directory` to configure the search path, but
-        # it doesn't feel right to mess with application-wide settings. Let's
-        # assume that the `.dll` is next to the `.py` file and load by full path.
-        libname = os.path.join(
-            os.path.dirname(__file__),
-            "{}.dll",
+    library_path = None
+    extension = ""
+    if platform.system() == "Darwin":
+        extension = ".dylib"
+    elif platform.system() == "Linux":
+        extension = ".so"
+    elif platform.system() == "Windows":
+        extension = ".dll"

+    # Try prebuilt platform-specific library first
+    path = os.path.join(
+        os.path.dirname(__file__),
+        "prebuilt/libuniffi_dnssec_prover_%s_%s%s"
+        % (platform.system().lower(), platform.machine().lower(), extension),
+    )
+    if os.path.isfile(path):
+        return ctypes.cdll.LoadLibrary(path)
    
+    # Try searching system paths
+    if not library_path:
+        library_path = ctypes.util.find_library("libuniffi_dnssec_prover")
+    if not library_path:
+        library_path = ctypes.util.find_library("uniffi_dnssec_prover")
    
+    # Platform-specific fallback locations
+    if not library_path:
+        if platform.system() == "Linux" and os.path.isfile(
+            "/usr/local/lib/libuniffi_dnssec_prover.so"
+        ):
+            library_path = "/usr/local/lib/libuniffi_dnssec_prover.so"
+        elif platform.system() == "Darwin" and os.path.isfile(
+            "/usr/local/lib/libuniffi_dnssec_prover.dylib"
+        ):
+            library_path = "/usr/local/lib/libuniffi_dnssec_prover.dylib"
    
+    if not library_path:
+        raise RuntimeError(
+            f"Can't find libuniffi_dnssec_prover library for {platform.system().lower()}_{platform.machine().lower()}. "
+            "Make sure to compile and install it, or place it in the prebuilt/ directory."
+        )
    
+    return ctypes.cdll.LoadLibrary(library_path)
```

Then, move the bindings file to the `src/embit/util/` directory.

## References

- [dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover)
- [uniffi Documentation](https://mozilla.github.io/uniffi-rs/)
- [BIP-353: DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki)
- [Rust Cross-compilation Guide](https://rust-lang.github.io/rustup/cross-compilation.html) 