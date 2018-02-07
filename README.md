# Bytecoin

## About

Welcome to the repository of Bytecoin. Here you will find source code and binaries of all components, wiki resources, and various useful tutorials.

## How to build binaries from source code

To build binaries you need to get dependencies and put them in the same directory where bytecoin directory resides:
* `git clone https://github.com/bcndev/bytecoin.git`
* `git clone https://github.com/LMDB/lmdb.git`

You also need Boost 1.58 or newer installed system-wide.

If you want to use tools like `clang-tidy`, run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` instead of `cmake`.

Bytecoin references source files directly by relative paths, so you do not need to separately build dependencies.

What you need to build the project:
* On Linux - developer essentials, cmake (3.5 or newer), make, gcc/g++ (5.4 or newer) [builing via cmake].
* On MacOS - XCode [building with provided XCode project].
* On Windows - Microsoft Visual Studio Community 2017 [building project after CMake integration].

Please note that we currently support building only 64-bit binaries.

## How to run binaries

The new Bytecoin stores blockchain, logs, and wallet cache in the "coin folder" located:
* On Mac at `~/Library/Application Support/bytecoin` (new location)
* On Linux at `~/.bytecoin` (just like before)
* On Windows at `%APPDATA%\Roaming\bytecoin` (new location)

If you have old bytecoin installed, the new one will import blocks from the old folder before downloading the rest from p2p.
Or you can download up-to-date blockchain data from [official site](https://blockchain.bytecoin.org) and place it in the new coin folder.

On decent computer full sync should take about 1-2 hours using SSD or 6-24 hours if using HDD.

Some benchmarks:
* MacBook Pro late 2013 with 16GB memory and PCI Express SSD - ~1 hour
* AMD FX 8320 8-core with 20GB memory and SATA HDD - 3 hours
* (very old) Athlon 64 II x2 240 with 4GB memory and SATA SSD - ~24 hours
* (very old) Athlon 64 II x2 240 with 2GB memory and ATA HDD - ~4 days
