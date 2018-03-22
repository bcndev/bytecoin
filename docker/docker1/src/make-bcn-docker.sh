#!/bin/bash

RESULT_MSG='Copy result build to save folder'

git clone https://github.com/bcndev/bytecoin.git
cd bytecoin
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure linux-x86_64 no-shared
time make -j4
echo 'Copy source openssl and compiled'
cp ./include/openssl/* ./
cp ./apps/openssl ./
cd ..

git clone https://github.com/LMDB/lmdb.git
mkdir -p build
cd build
cmake ..
time make -j4

echo $RESULT_MSG
cp -v ../bin/* /save

cd ../..
git clone https://github.com/bcndev/bytecoin-gui.git
cd bytecoin-gui
mkdir -p build
cd build
cmake ..
time make -j4
echo $RESULT_MSG
cp -v ../bin/* /save

echo Remove sources
cd ../.. && rm -rf bytecoin-gui && rm -rf bytecoin
