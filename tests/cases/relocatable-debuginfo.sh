#!/bin/bash
source "$(dirname "$0")"/common.inc

cat <<EOF > $t/a.c
int compute(int x) { return x * 7; }
EOF

cat <<EOF > $t/b.c
#include <stdio.h>
int compute(int);
int main() { printf("%d\n", compute(6)); }
EOF

$CC -g -c $t/a.c -o $t/a.o
$CC -g -c $t/b.c -o $t/b.o

# The merged object must carry both objects' DWARF, marked debug.
$mold -r -arch $ARCH -platform_version macos 15.0 15.0 -o $t/merged.o $t/a.o $t/b.o
dwarfdump --debug-info $t/merged.o > $t/dwarf
[ "$(grep -c DW_TAG_compile_unit $t/dwarf)" = 2 ]

# A final link's OSO stab names the merged object as the debug source.
$CC --ld-path=$mold -g -o $t/exe $t/merged.o
$t/exe | grep -q '^42$'
nm -pa $t/exe | grep -q 'OSO.*merged.o'

# Apple's linker accepts the merged object too.
$CC -g -o $t/exe2 $t/merged.o
$t/exe2 | grep -q '^42$'

# lldb sets a source-level breakpoint in code that came through -r.
lldb -b -o 'b compute' -o run -o 'p x' $t/exe > $t/lldb.log 2>&1 || true
grep -q 'stop reason = breakpoint' $t/lldb.log
grep -q '(int) 6' $t/lldb.log
