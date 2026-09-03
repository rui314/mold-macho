#!/bin/bash
source "$(dirname "$0")"/common.inc

# A SUBTRACTOR relocation and the UNSIGNED it pairs with share one
# offset; their order in the object is the pairing. Swift emits
# thousands of such 4-byte pairs (relative pointers) per section. The
# relocations were once sorted by offset with an unstable sort, which
# swapped some pairs; the lone 4-byte UNSIGNED was then written as 8
# bytes, corrupting the next entry or overrunning the section.
{
  echo '.text'
  for i in $(seq 0 199); do
    echo ".globl _f$i"
    echo "_f$i:"
    echo "  ret"
  done
  echo '.section __TEXT,__const'
  echo '.p2align 2'
  echo '.globl _table'
  echo '_table:'
  for i in $(seq 0 199); do
    echo "  .long _f$i - _table"
  done
} > $t/a.s
$CC -o $t/a.o -c $t/a.s

cat <<EOF | $CC -o $t/main.o -c -xc -
#include <stdio.h>
#include <stdint.h>
extern const int32_t table[200];
extern char f0, f1, f199;
int main() {
  const char *base = (const char *)table;
  int ok = base + table[0] == &f0 && base + table[1] == &f1 &&
           base + table[199] == &f199;
  printf("%s\n", ok ? "OK" : "BAD");
}
EOF

$CC --ld-path=$mold -o $t/exe $t/main.o $t/a.o
$t/exe | grep -q '^OK$'
