#! /bin/bash

mkdir -p bin
gcc $1.c -o$1 -I$HOME/cntls/include -L$HOME/cntls/lib -lcrypto -ldl
mv $1 bin
