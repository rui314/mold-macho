#!/bin/bash
source "$(dirname "$0")"/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc - -fmodules
#include <zlib.h>
int main() {}
EOF

$CC --ld-path=$mold -o $t/exe $t/a.o
