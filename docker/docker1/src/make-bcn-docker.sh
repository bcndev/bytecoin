#!/bin/bash

git clone https://github.com/bcndev/bytecoin.git
cd bytecoin
git clone https://github.com/LMDB/lmdb.git
mkdir -p build
cd build
cmake ..
time make -j4

cd ../..
git clone https://github.com/bcndev/bytecoin-gui.git
cd bytecoin-gui
mkdir -p build
cd build
cmake ..
time make -j4
cp -v ../../bytecoin/bin/* /save/
cp -v ../bin/* /save/
