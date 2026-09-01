#!/bin/bash
source "$(dirname "$0")"/common.inc

# Only x86-64 clang materializes doubles from __literal8; arm64 code
# synthesizes them with mov/movk sequences.
CC="cc -arch x86_64"
arch -x86_64 /usr/bin/true 2> /dev/null || skip

cat <<EOF | $CC -o $t/a.o -c -xc -
double pi1() { return 3.1415926535; }
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
double pi2() { return 3.1415926535; }
int main() {}
EOF

# The two identical 8-byte literals coalesce into one.
$CC --ld-path=$mold -o $t/exe $t/a.o $t/b.o
objdump -h $t/exe | grep -Eq ' __literal8\s+00000008\s'
