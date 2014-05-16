#!/bin/sh

set -e
set -x

mkdir -p ./lib

git clone  --depth 1 https://github.com/bitwiseshiftleft/sjcl.git ./lib/sjcl
pushd ./lib/sjcl
./configure --without-all --with-random --with-bn
make
