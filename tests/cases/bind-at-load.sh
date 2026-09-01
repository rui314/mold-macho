#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF2 | $CC -o $t/a.o -c -xc -
#include <stdio.h>
int main() { printf("hi\n"); }
EOF2

$CC --ld-path=$mold -o $t/exe $t/a.o -Wl,-bind_at_load
otool -h $t/exe | grep -iq bindatload || otool -hv $t/exe | grep -q BINDATLOAD
$t/exe | grep hi
