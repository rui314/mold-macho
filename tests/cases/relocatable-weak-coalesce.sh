#!/bin/bash
source "$(dirname "$0")"/common.inc

# ld64 -r keeps one copy of each weak definition (C++ inline
# functions and templates, Swift's per-object metadata records), the
# marker still on it so the final link can auto-hide it. We carried
# every copy: Xcode's -r prelink of NetNewsWire's RSCore package had a
# __DATA,__const twice the size of ld-prime's, and a __text 27KB
# larger. Unwind records of the dropped copies go with them.
cat <<EOF2 | $CC -O2 -o $t/a.o -c -xc++ -
template <typename T> struct Box { T v; __attribute__((noinline)) T get() const { return v; } };
inline int twice(int x) { return 2 * x; }
int use_a(Box<int> *b) { return b->get() + twice(1); }
EOF2
cat <<EOF2 | $CC -O2 -o $t/b.o -c -xc++ -
template <typename T> struct Box { T v; __attribute__((noinline)) T get() const { return v; } };
inline int twice(int x) { return 2 * x; }
int use_a(Box<int> *);
int main() { Box<int> b = {3}; return use_a(&b) + b.get() + twice(2) - 12; }
EOF2
$mold -r -arch $ARCH -o $t/r.o $t/a.o $t/b.o
nm -m $t/r.o > $t/nm
[ "$(grep -c '__ZNK3BoxIiE3getEv$' $t/nm)" = 1 ]
grep -q 'weak external automatically hidden __ZNK3BoxIiE3getEv' $t/nm
# One __LD,__compact_unwind record per surviving function.
$CC --ld-path=$mold -o $t/exe $t/r.o
$t/exe
