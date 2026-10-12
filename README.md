# mold-macho: mold for macOS

mold-macho is a Mach-O linker for macOS, written in Rust as a port of
the [mold linker](https://github.com/rui314/mold) to Apple platforms.
It is a drop-in replacement for Apple's `ld` for common workloads: it
accepts ld64's command line, and links working, correctly code-signed
executables, dylibs and bundles for arm64 and x86-64 macOS.

C, C++, Objective-C, Swift and Rust programs link and run, including
real-world projects (ripgrep builds and passes its full test suite;
the C++ mold tree with vendored tbb/zstd/zlib builds at -O3; the
linker links itself). Debugging works (stabs for lldb/dsymutil), and
so do C++ exceptions, thread-locals, LTO, auto-linking, frameworks and
Objective-C selector stubs.

This project has been merged into the main [mold repository](https://github.com/rui314/mold).
Development continues there.
