#!/bin/sh

if [ $# -lt 1 ];
then
    echo "Usage: $0 <path/to/poc>"
    exit 1
fi

LD_PRELOAD=./libc.so.6 ./ld-linux-x86-64.so.2 $1
