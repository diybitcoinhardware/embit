This document describes how to build a library from **libsecp256k1** fork -
[**secp256k1-zkp**](https://github.com/ElementsProject/secp256k1-zkp).

# Building the library on Linux or MacOS

Just run:

```sh
make
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

To build the DLL and the companion library from the source code type:

```shell
make
```

To clean build directory use:

```shell
make clean
```
