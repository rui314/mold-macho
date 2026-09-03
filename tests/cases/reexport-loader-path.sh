#!/bin/bash
source "$(dirname "$0")"/common.inc

# A framework binary is reached through the X.framework/X symlink, but
# dyld resolves its @loader_path from the real file in Versions/A, and
# the framework's LC_RPATH entries are written for that location.
# Xcode's XCTest.framework re-exports XCTestCore through
# @rpath/XCTestCore.framework/... with the rpath
# @loader_path/../../../../PrivateFrameworks/; resolved from the
# symlink's directory, the re-export was not found and every XCTest
# symbol was undefined in test bundles.
mkdir -p $t/Library/Frameworks/Foo.framework/Versions/A \
         $t/Library/PrivateFrameworks/Bar.framework/Versions/A

cat <<EOF | $CC -o $t/bar.o -c -xc -
int bar(void) { return 7; }
EOF
$CC --ld-path=$mold -shared -o $t/Library/PrivateFrameworks/Bar.framework/Versions/A/Bar $t/bar.o \
  -Wl,-install_name,@rpath/Bar.framework/Versions/A/Bar
ln -sf Versions/A/Bar $t/Library/PrivateFrameworks/Bar.framework/Bar

cat <<EOF | $CC -o $t/foo.o -c -xc -
int foo(void) { return 1; }
EOF
$CC --ld-path=$mold -shared -o $t/Library/Frameworks/Foo.framework/Versions/A/Foo $t/foo.o \
  -Wl,-install_name,@rpath/Foo.framework/Versions/A/Foo \
  -Wl,-rpath,@loader_path/../../../../PrivateFrameworks/ \
  -Wl,-reexport_library,$t/Library/PrivateFrameworks/Bar.framework/Versions/A/Bar
ln -sf Versions/A/Foo $t/Library/Frameworks/Foo.framework/Foo

# The client names Foo through the symlink and calls bar() through the
# re-export.
cat <<EOF | $CC -o $t/main.o -c -xc -
#include <stdio.h>
int bar(void);
int main() { printf("%d\n", bar()); }
EOF
$CC --ld-path=$mold -o $t/exe $t/main.o -F$t/Library/Frameworks -framework Foo \
  -Wl,-rpath,$t/Library/Frameworks -Wl,-rpath,$t/Library/PrivateFrameworks
$t/exe | grep -q '^7$'
