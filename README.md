# Bytecoin

[![Build Status](https://dev.azure.com/bcndev/bytecoin/_apis/build/status/bytecoin-daemons?branchName=releases/3.4.4)](https://dev.azure.com/bcndev/bytecoin/_build/latest?definitionId=1&branchName=releases/3.4.4)

## About

Welcome to the repository of Bytecoin. Here you will find source code, instructions, wiki resources, and integration tutorials.

Contents
* Building on Linux 64-bit
* Building on Mac OSX
* Building on Windows
* Building on other platforms

## Building on Linux 64-bit

All commands below work on Ubuntu 18.*, other distributions may need different command set.

### Building with standard options

Create directory `bcndev` somewhere and go there:
```
$> mkdir bcndev
$> cd bcndev
```

To go futher you have to have a number of packages and utilities. You need at least gcc 5.4.

* `build-essential` package:
    ```
    $bcndev> sudo apt-get install build-essential
    ```

* `libudev`:
    ```
    sudo apt-get install libudev-dev
    ```
    
* CMake (3.0 or newer):
    ```
    $bcndev> sudo apt-get install cmake
    $bcndev> cmake --version
    ```
    If version is too old, follow instructions on [the official site](https://cmake.org/download/).

* Boost (1.65 or newer):
    We use boost as a header-only library via find_boost package. So, if your system has boost installed and set up, it will be used automatically.

    Note - there is a bug in `boost::asio` 1.66 that affects `bytecoind`. Please use either version 1.65 or 1.67+.
    ```
    $bcndev> sudo apt-get install libboost-dev
    ```
    If the latest boost installed is too old (e.g. for Ubuntu 16.*), then you need to download and unpack boost into the `bcndev/boost` folder.

    ```
    $bcndev> wget -c 'https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz'
    $bcndev> tar -xzf ./boost_1_69_0.tar.gz
    $bcndev> rm ./boost_1_69_0.tar.gz
    $bcndev> mv ./boost_1_69_0/ ./boost/
    ```

* OpenSSL (1.1.1 or newer):
    Install OpenSSL to `bcndev/openssl` folder. (In below commands use switch `linux-x86_64-clang` instead of `linux-x86_64` if using clang.)
    ```
    $bcndev> git clone --single-branch --branch OpenSSL_1_1_1b --depth 1 https://github.com/openssl/openssl.git
    $bcndev> cd openssl
    $bcndev/openssl> ./Configure linux-x86_64 no-shared
    $bcndev/openssl> make -j8
    $bcndev/openssl> cd ..
    ```

* LMDB
    Source files are referenced via relative paths, so you do not need to separately build it:
    Please note, we use LMDB only when building 64-bit daemons. For 32-bit daemons SQLite is used instead.

    Difference to official LMDB repository is lifted 2GB database limit if built by MSVC (even of 64-bit machine).
    ```
    $bcndev> git clone https://github.com/bcndev/lmdb.git

    ```

Git-clone (or git-pull) Bytecoin source code in that folder:
```
$bcndev> git clone https://github.com/bcndev/bytecoin.git
```

Create build directory inside bytecoin, go there and run CMake and Make:
```
$bcndev> mkdir -p bytecoin/build
$bcndev> cd bytecoin/build
$bcndev/bytecoin/build> cmake ..
$bcndev/bytecoin/build> make -j8
```

Check built binaries by running them from `../bin` folder
```
$bcndev/bytecoin/build> ../bin/bytecoind -v
```

## Building on Mac OSX

### Building with standard options (10.11 El Capitan or newer)

You need command-line tools. Either get XCode from an App Store or run 'xcode-select --install' in terminal and follow instructions. First of all, you need [Homebrew](https://brew.sh).

Then open terminal and install CMake and Boost:

* `brew install cmake`
* `brew install boost`

Create directory `bcndev` somewhere and go there:
```
$~/Downloads> mkdir bcndev
$~/Downloads> cd bcndev
```

Git-clone (or git-pull) Bytecoin source code in that folder:
```
$bcndev> git clone https://github.com/bcndev/bytecoin.git
```

Put LMDB source code in `bcndev` folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$~/Downloads/bcndev> git clone https://github.com/bcndev/lmdb.git
```

Install OpenSSL to `bcndev/openssl` folder:
```
$~/Downloads/bcndev> git clone --single-branch --branch OpenSSL_1_1_1b --depth 1 https://github.com/openssl/openssl.git
$~/Downloads/bcndev> cd openssl
$~/Downloads/bcndev/openssl> ./Configure darwin64-x86_64-cc no-shared -mmacosx-version-min=10.11
$~/Downloads/bcndev/openssl> make -j8
$~/Downloads/bcndev/openssl> cd ..
```

Create build directory inside bytecoin, go there and run CMake and Make:
```
$~/Downloads/bcndev> mkdir bytecoin/build
$~/Downloads/bcndev> cd bytecoin/build
$~/Downloads/bcndev/bytecoin/build> cmake ..
$~/Downloads/bcndev/bytecoin/build> make -j8
```

Check built binaries by running them from `../bin` folder:
```
$bcndev/bytecoin/build> ../bin/bytecoind -v
```

## Building on Windows

You need Microsoft Visual Studio Community 2017. [Download](https://www.visualstudio.com/vs/) and install it selecting `C++`, `git`, `cmake integration` packages.
Run `Visual Studio x64 command prompt` from start menu.

Create directory `bcndev` somewhere:
```
$C:\> mkdir bcndev
$C:\> cd bcndev
```

Boost (1.65 or newer):
    We use boost as a header-only library via find_boost package. So, if your system has boost installed and set up, it will be used automatically. If not, you need to download and unpack boost into bcndev/boost folder.

Git-clone (or git-pull) Bytecoin source code in that folder:
```
$C:\bcndev> git clone https://github.com/bcndev/bytecoin.git
```

Put LMDB in the same folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$C:\bcndev> git clone https://github.com/bcndev/lmdb.git
```

Download amalgamated [SQLite 3](https://www.sqlite.org/download.html) and unpack it into the same folder (source files are referenced via relative paths, so you do not need to separately build it).

You need to build openssl, first install ActivePerl (select "add to PATH" option, then restart console):
```
$C:\bcndev> git clone --single-branch --branch OpenSSL_1_1_1b --depth 1 https://github.com/openssl/openssl.git
$C:\bcndev> cd openssl
$C:\bcndev\openssl> perl Configure VC-WIN64A no-shared no-asm
$C:\bcndev\openssl> nmake
$C:\bcndev\openssl> cd ..
```
If you want to build 32-bit binaries, you will also need 32-bit build of openssl in separate folder (configuring openssl changes header files, so there is no way to have both 32-bit and 64-bit versions in the same folder):
```
$C:\bcndev> git clone --single-branch --branch OpenSSL_1_1_1b --depth 1 https://github.com/openssl/openssl.git openssl32
$C:\bcndev> cd openssl32
$C:\bcndev\openssl> perl Configure VC-WIN32 no-shared no-asm
$C:\bcndev\openssl> nmake
$C:\bcndev\openssl> cd ..
```

Now launch Visual Studio, in File menu select `Open Folder`, select `C:\bcndev\bytecoin` folder.
Wait until CMake finishes running and `Build` appears in main menu.
Select `x64-Debug` or `x64-Release` from standard toolbar, and then `Build/Build Solution` from the main menu.

## Building with options

You can build daemons that use SQLite istead of LMDB on any platform by providing options to CMake.
You may need to clean 'build' folder, if you built with default options before, due to cmake aggressive caching.

```
$bytecoin/build> cmake -DUSE_SQLITE=1 ..
$bytecoin/build> time make -j8
```

## Building on 32-bit x86 platforms, iOS, Android and other ARM platforms

Bytecoin works on 32-bit systems if SQLite is used instead of LMDB (we've experienced lots of problems building and running with lmdb in 32-bit compatibility mode, especially on iOS).

We build official x86 32-bit version for Windows only, because there is zero demand for 32-bit version for Linux or Mac.

Building source code for iOS, Android, Raspberry PI, etc is possible (we have experimental `bytecoind` and `walletd` running on ARM64 iPhone) but requires major skills on your part. __TBD__

## Building on Big-Endian platforms

Currently bytecoin does not work out of the box on any Big-Endian platform, due to some endianess-dependent code. This may be fixed in the future. If you wish to run on Big-Endian platform, please contact us.

## Building with parameters

If you want to use tools like `clang-tidy`, run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..` instead of `cmake ..`
