# Building secp256k1 for `embit`
`embit` PyPI artifacts do not include prebuilt `libsecp256k1` binaries.
If you want the optional ctypes backend, build and install `libsecp256k1` locally.


## Clone `embit` recursively
We are using the **libsecp256k1** fork - [**secp256k1-zkp**](https://github.com/ElementsProject/secp256k1-zkp).

Start by cloning `embit` with the `--recursive` flag:
```sh
git clone --recursive https://github.com/diybitcoinhardware/embit.git
```

This will automatically pull in the `libsecp256k1-zkp` repo and checkout the correct commit within that repo.


## Building the library
This directory (`secp256k1/` in the `embit` root) already has a fully-configured Makefile to run the compilation for you.

On your target platform run:
```sh
make
```

Install the resulting library into a standard system library location so the dynamic loader can find it (for example `/usr/local/lib` on Unix-like systems), then refresh your linker environment as needed for your platform.

Note: runtime lookup prefers local `secp256k1/secp256k1-zkp/.libs` and system library paths.
`src/embit/util/prebuilt` is still checked last for compatibility with older local setups, but binaries are not shipped by this project.

To clean build directory use:
```shell
make clean
```


# Cross-compiling Windows DLL

## Toolchain install

### Linux

In the console type:

```shell
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
```

### Mac

Assuming that [Homebrew](https://brew.sh/) package manager is installed, in the console type:

```shell
brew install mingw-w64
brew install --cask xquartz
brew install --cask wine-stable
```

### Windows

Assuming that [Chocolatey](https://chocolatey.org/) package manager is installed, in the **Powershell** type:

```shell
choco install mingw make
```

## Building the library

To build the Windows DLL and the companion library from other platforms run:

```shell
make CROSS_DLL=1
```
