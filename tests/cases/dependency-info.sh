#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF2 | $CC -o $t/a.o -c -xc -
int main() {}
EOF2

$CC --ld-path=$mold -o $t/exe $t/a.o -Wl,-dependency_info,$t/deps
$t/exe

# The file is opcode-prefixed NUL-terminated strings; look for our
# input and output paths in it.
tr '\0' '\n' < $t/deps > $t/deps.txt
grep -q 'a.o' $t/deps.txt
grep -q 'exe' $t/deps.txt
grep -q 'libSystem' $t/deps.txt
