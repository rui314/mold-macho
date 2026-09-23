#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF2 | $CC -o $t/a.o -c -xc -
int foo() { return 1; }
int bar() { return 2; }
int main() { return 0; }
EOF2

cat <<EOF2 > $t/list
# only foo is exported
_foo
EOF2

$CC --ld-path=$mold -o $t/exe $t/a.o -Wl,-exported_symbols_list,$t/list
dyld_info -exports $t/exe > $t/exports
grep -q _foo $t/exports
not grep -q _bar $t/exports

# What the list leaves unexported becomes a private external: a local
# in the symbol table ("was a private external"), _main and the
# header symbol included when the list omits them, as ld64 has it.
nm -m $t/exe > $t/nm
grep -q 'non-external (was a private external) _bar' $t/nm
grep -q 'non-external (was a private external) _main' $t/nm
grep -q 'non-external (was a private external) __mh_execute_header' $t/nm
grep -q ' external _foo' $t/nm

# -unexported_symbols_list demotes only what it names.
echo _bar > $t/unlist
$CC --ld-path=$mold -o $t/exe2 $t/a.o -Wl,-unexported_symbols_list,$t/unlist
dyld_info -exports $t/exe2 > $t/exports2
grep -q _foo $t/exports2
not grep -q _bar $t/exports2
nm -m $t/exe2 > $t/nm2
grep -q 'non-external (was a private external) _bar' $t/nm2
grep -q ' external _main' $t/nm2
grep -q ' external __mh_execute_header' $t/nm2

# A dylib definition the list leaves out is no -dead_strip root.
$CC --ld-path=$mold -dynamiclib -o $t/libfoo.dylib $t/a.o \
  -Wl,-exported_symbols_list,$t/list,-dead_strip
nm $t/libfoo.dylib > $t/nm3
grep -q _foo $t/nm3
not grep -q _bar $t/nm3
