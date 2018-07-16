#!/bin/sh

LD_PRELOAD=./libc.so.6 ./ld-linux-x86-64.so.2 $1
