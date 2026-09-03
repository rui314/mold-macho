#!/bin/bash
source "$(dirname "$0")"/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc - -fmodules
#include <zlib.h>
int main() {}
EOF

$CC --ld-path=$mold -o $t/exe $t/a.o

# An auto-link option naming a library or framework that cannot be
# found is ignored without a word, as in ld64: header-only SDK
# frameworks such as CoreAudioTypes have a framework directory but no
# binary, and every Swift object importing one carries `-framework
# CoreAudioTypes` (CotEditor's build printed a warning per object).
mkdir -p $t/mm
cat <<EOF > $t/mm/module.modulemap
module Foo { header "foo.h" link framework "NoSuchFramework" link "nosuchlib" }
EOF
echo 'int foo(void);' > $t/mm/foo.h
cat <<EOF | $CC -o $t/b.o -c -xc - -fmodules -fmodules-cache-path=$t/mm/cache -I$t/mm
#include "foo.h"
int main() {}
EOF
otool -l $t/b.o | grep -A3 LC_LINKER_OPTION | grep -q 'string #1 -lnosuchlib'
$CC --ld-path=$mold -o $t/exe2 $t/b.o 2> $t/stderr
[ ! -s $t/stderr ]
