#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF2 | $CC -o $t/a.o -c -xc -
int foo() { return 1; }
EOF2

cat <<EOF2 | $CC -o $t/b.o -c -xc -
int foo() { return 2; }
int main() { return 0; }
EOF2

! $CC --ld-path=$mold -o $t/exe $t/a.o $t/b.o 2> $t/log
grep -q 'duplicate symbol: _foo' $t/log
