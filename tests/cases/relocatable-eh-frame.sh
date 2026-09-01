#!/bin/bash
source "$(dirname "$0")"/common.inc

# DWARF-only unwind info exists on x86-64; arm64 compilers always
# emit compact unwind.
[ $ARCH = x86_64 ] || skip

# .cfi_escape defeats compact-unwind encoding, so this frame's unwind
# info exists only as a DWARF FDE; .cfi_personality gives its CIE a
# personality, exercising the one relocation __eh_frame carries.
cat <<EOF | $CC -o $t/a.o -c -xassembler -
.globl _through_asm
_through_asm:
 .cfi_startproc
 .cfi_personality 155, ___gxx_personality_v0
 .cfi_escape 0x00
 pushq %rbp
 .cfi_def_cfa_offset 16
 .cfi_offset %rbp, -16
 movq %rsp, %rbp
 .cfi_def_cfa_register %rbp
 callq _thrower
 popq %rbp
 retq
 .cfi_endproc
.subsections_via_symbols
EOF

cat <<EOF | $CXX -o $t/b.o -c -xc++ -
#include <cstdio>
extern "C" void thrower() { throw 40; }
extern "C" void through_asm();
int main() { try { through_asm(); } catch (int e) { printf("caught %d\n", e + 2); } }
EOF

$mold -r -arch $ARCH -platform_version macos 15.0 15.0 -o $t/merged.o $t/a.o $t/b.o

# The merged object carries __eh_frame with the personality's GOT
# relocation, the shape compilers emit.
otool -l $t/merged.o | grep -q 'sectname __eh_frame'
otool -r $t/merged.o > $t/relocs
sed -n '/__eh_frame/,+3p' $t/relocs | grep -q '1     2      1      4'

# The exception unwinds through the assembly frame after a final link
# by either linker.
$CXX --ld-path=$mold -o $t/exe $t/merged.o
$t/exe | grep -q 'caught 42'
$CXX -o $t/exe2 $t/merged.o
$t/exe2 | grep -q 'caught 42'
