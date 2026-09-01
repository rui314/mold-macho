#!/bin/bash
source "$(dirname "$0")"/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
void hello() {
  printf("Hello world\n");
}
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
void hello();
int main() {
  hello();
}
EOF

$CC --ld-path=$mold -o $t/exe $t/a.o $t/b.o -Wl,-map,$t/map

# ld64's map: file 0 is "linker synthesized", real objects follow in
# link order; sections and symbols are tab-separated with a size column.
grep -Eq '^\[  0\] linker synthesized$' $t/map
grep -Eq '^\[  1\] .*/a.o$' $t/map
grep -Eq '^\[  2\] .*/b.o$' $t/map
grep -Eq $'^0x[0-9A-Fa-f]+\t0x[0-9A-Fa-f]+\t__TEXT\t__text$' $t/map
grep -Eq $'^0x[0-9A-Fa-f]+\t0x[0-9A-Fa-f]+\t\[  0\] __mh_execute_header$' $t/map
grep -Eq $'^0x[0-9A-Fa-f]+\t0x[0-9A-Fa-f]+\t\[  1\] _hello$' $t/map
grep -Eq $'^0x[0-9A-Fa-f]+\t0x[0-9A-Fa-f]+\t\[  2\] _main$' $t/map
! grep -q ltmp $t/map || false
