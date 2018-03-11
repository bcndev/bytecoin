# Bytecoin

## About

Welcome to the repository of Bytecoin. Here you will find source code, instructions, wiki resources, and integration tutorials.

Contents
* Building on Linux 64-bit
* Building on Mac OSX
* Building on Windows
* Building on other platforms

## Building on Linux 64-bit

All commands below are adapted for Ubuntu, other distributions may need an other command set.

### Building with standard options

To go futher you have to have a number of packages and utilities.

* `build-essential` package:
    ```
    $> sudo apt-get install build-essential
    ```

* CMake (3.5 or newer):
    ```
    $> sudo apt-get install cmake
    $> cmake --version
    ```
    If version is too old, follow instructions on [the official site](https://cmake.org/download/).

* Boost (1.58 or newer):
    ```
    $> sudo apt-get install libboost-all-dev
    $> cat /usr/include/boost/version.hpp | grep "BOOST_LIB_VERSION"
    ```
    If version is too old, follow instructions on [the official site](http://www.boost.org/users/download/).

Then create directory `bcndev` somewhere and go there:
```
$> mkdir bcndev
$> cd bcndev
```

Git-clone (or git-pull) Bytecoin source code in that folder:
```
$bcndev> git clone https://github.com/bcndev/bytecoin.git
```

Put LMDB source code in `bcndev` folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$bcndev> git clone https://github.com/LMDB/lmdb.git
```

Create build directory inside bytecoin, go there and run CMake and Make:
```
$bcndev> mkdir bytecoin/build
$bcndev> cd bytecoin/build
$bcndev/bytecoin/build> cmake ..
$bcndev/bytecoin/build> time make -j4
```

Check built binaries by running them from `../bin` folder
```
$bcndev/bytecoin/build> ../bin/bytecoind -v
```

### Building with specific options

Install OpenSSL to `bcndev/openssl` folder. (Use switch `linux-x86_64-clang` instead of `linux-x86_64` if using clang.)
```
$bcndev> git clone https://github.com/openssl/openssl.git
$bcndev> cd openssl
$bcndev/openssl> ./Configure linux-x86_64
$bcndev/openssl> time make -j4
$bcndev/openssl> cd ..
```

Download amalgamated [SQLite 3](https://www.sqlite.org/download.html) and unpack it into `bcndev/sqlite` folder (source files are referenced via relative paths, so you do not need to separately build it).

Below are the commands which add OpenSSL support and switch from LMDB to SQLite by providing options to CMake:

```
$bcndev> mkdir bytecoin/build
$bcndev> cd bytecoin/build
$bcndev/bytecoin/build> cmake -DBYTECOIN_SSL=1 -DBYTECOIN_SQLITE=1 ..
$bcndev/bytecoin/build> time make -j4
```

## Building on Mac OSX

### Building with standard options (10.11 El Capitan or newer)

You need command-line tools. Either get XCode from an App Store or run 'xcode-select --install' in terminal and follow instructions. First of all, you need [Homebrew](https://brew.sh).

Then open terminal and install CMake and Boost:

* `brew install cmake`
* `brew install boost`

Create directory `bcndev` somewhere and go there:
```
$~/Downloads> mkdir <path-to-bcndev-folder>
$~/Downloads> cd <path-to-bcndev-folder>
```

Git-clone (or git-pull) Bytecoin source code in that folder:
```
$bcndev> git clone https://github.com/bcndev/bytecoin.git
```

Put LMDB source code in `bcndev` folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$bcndev> git clone https://github.com/LMDB/lmdb.git
```

Create build directory inside bytecoin, go there and run CMake and Make:
```
$bcndev> mkdir bytecoin/build
$bcndev> cd bytecoin/build
$bcndev/bytecoin/build> cmake ..
$bcndev/bytecoin/build> time make -j4
```

Check built binaries by running them from `../bin` folder:
```
$bcndev/bytecoin/build> ../bin/bytecoind -v
```

### Building with specific options

Binaries linked with Boost installed by Homebrew will work only on your computer's OS X version or newer, but not on older versions like El Capitan.

If you need binaries to run on all versions of OS X starting from El Capitan, you need to build boost yourself targeting El Capitan SDK.

Download [Mac OSX 10.11 SDK](https://github.com/phracker/MacOSX-SDKs/releases) and unpack to it into `Downloads` folder

Download and unpack [Boost](https://boost.org) to `Downloads` folder.

Then build and install Boost:
```
$~> cd ~/Downloads/boost_1_58_0/
$~/Downloads/boost_1_58_0> ./bootstrap.sh
$~/Downloads/boost_1_58_0> ./b2 -a -j 4 cxxflags="-stdlib=libc++ -std=c++14 -mmacosx-version-min=10.11 -isysroot/Users/user/Downloads/MacOSX10.11.sdk" install`
```

Install OpenSSL to `bcndev/openssl` folder:
```
$~/Downloads/bcndev> git clone https://github.com/openssl/openssl.git
$~/Downloads/bcndev> cd openssl
```

If you need binaries to run on all versions of OS X starting from El Capitan, you need to build OpenSSL targeting El Capitan SDK.
```
$bcndev/openssl> ./Configure darwin64-x86_64-cc no-shared -mmacosx-version-min=10.11 -isysroot/Users/user/Downloads/MacOSX10.11.sdk
```
Otherwise just use
```
$bcndev/openssl> ./Configure darwin64-x86_64-cc no-shared
```

```
$bcndev/openssl> time make -j4
$bcndev/openssl> cd ..
```

Download amalgamated [SQLite 3](https://www.sqlite.org/download.html) and unpack it into `bcndev/sqlite` folder (source files are referenced via relative paths, so you do not need to separately build it).

You add OpenSSL support or switch from LMDB to SQLite by providing options to CMake:

```
$bcndev> mkdir bytecoin/build
$bcndev> cd bytecoin/build
$bcndev/bytecoin/build> cmake -DBYTECOIN_SSL=1 -DBYTECOIN_SQLITE=1 ..
$bcndev/bytecoin/build> time make -j4
```

## Building on Windows

You need Microsoft Visual Studio Community 2017. [Download](https://microsoft.com) and install it selecting `C++`, `git`, `cmake integration` packages.

Get [Boost](https://boost.org) and unpack it into a folder of your choice. We will use `C:\boost_1_58_0` in the further examples.

Run `Visual Studio x64 command prompt` from start menu.

Build boost
```
$> cd C:\boost_1_58_0
$C:\boost_1_58_0> bootstrap.bat
$C:\boost_1_58_0> b2.exe address-model=64 link=static
```

Set boost environment variables, right-click Computer in start menu, select `Properties`, then click `advanced system settings`, `environment variables`.

Set `BOOST_ROOT` to `C:\boost_1_58_0`

Set `BOOST_INCLUDEDIR` to `C:\boost_1_58_0`

Set `BOOST_LIBRARYDIR` to `C:\boost_1_58_0\stage\lib`

Now create directory `bcndev` somewhere
```
$C:\> mkdir bcndev
$C:\> cd bcndev
```

You need bytecoin source code
```
$C:\bcndev> git clone https://github.com/bcndev/bytecoin.git
```

You need lmdb in the same folder (source files are referenced via relative paths, so you do not need to separately build it)
```
$C:\bcndev> git clone https://github.com/LMDB/lmdb.git
```

Now launch Visual Studio, in File menu select `Open Folder`, select `C:\bcndev\bytecoin` folder.
Wait until CMake finishes running and `Build` appears in main menu.
Select `x64-Debug` or `x64-Release` from standard toolbar, and then `Build/Build Solution` from the main menu.

You cannot add options to CMake running inside Visual Studio so just edit `CMakeLists.txt` and set `BYTECOIN_SSL` or `BYTECOIN_SQLITE` to `ON` if you wish to build with them.

## Building on 32-bit x86 platforms, iOS, Android and other ARM platforms

Bytecoin works on 32-bit systems if SQLite is used instead of LMDB (we've experienced lots of problems building and running with lmdb in 32-bit compatibility mode, especially on iOS).

Therefore SQLite option is automatically selected by CMake on 32-bit platforms and you must have SQLite downloaded as explained in appropriate sections above.

We build official x86 32-bit version for Windows only, because there is zero demand for 32-bit version for Linux or Mac.

Building source code for iOS, Android, Raspberry PI, etc is possible (we have experimental `bytecoind` and `walletd` running on ARM64 iPhone) but requires major skills on your part. __TBD__

## Building on Big-Endian platforms

Currently it is impossible to run Bytecoin on any Big-Endian platform, due to lots of endianess-dependent code. This may be fixed in the future. If you wish to run on Big-Endian platform, please contact us.

## Building with parameters

If you want to use tools like `clang-tidy`, run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..` instead of `cmake ..`
