# Parity with ld-prime

The reference is Apple's linker as shipped with Xcode 26 and 27
("ld-prime"; `ld -version_details` reports 27037). Parity is measured
by running every test script twice from the same directory, once with
`mold` pointing at this linker and once pointing at `/usr/bin/ld`, and
comparing every Mach-O file both runs produce: load commands and
section attributes (`otool -l`), the symbol table (`nm -m`), the export
trie, fixups and dependent libraries (`xcrun dyld_info`), the header
flags and the code signature. Addresses are normalized away; what's
compared is structure. Each rule that was made to match has a test
assertion that holds for both linkers.

On the test suite as of this writing, 799 output files are compared
and 15 differ, all in the cases below.

## Deliberate differences

- **The linker's tool entry in `LC_BUILD_VERSION`.** ld-prime's
  `build_tool_version` is tool 3 (`ld`) with its own version; ours is
  tool 54321 with version 1, so `otool -l | grep 'tool 54321'` finds
  our output. Claiming to be Apple's linker would mislead tooling that
  keys on the version.

- **A defined class's folded class reference.** From macOS 15 on both
  linkers fold `__objc_classrefs` into the GOT. For a class the image
  itself defines, ld-prime sometimes keeps a rebased GOT slot and
  sometimes relaxes the load to a direct address computation, by an
  undocumented per-reference heuristic. We always relax (no slot),
  which is self-consistent and smaller; the class address and every
  runtime check are the same either way. (2 files)

- **Order of the read-only Objective-C string pools.** Within `__TEXT`,
  ld-prime places `__objc_methname` after `__objc_methtype`, and after
  `__cstring` when the selector names are synthesized, by a rule that
  doesn't reduce to first-seen order. We keep first-seen order. The
  contents are identical. (6 files)

- **Synthetic local names in a `-r` output.** Both linkers name the
  anonymous atoms of a relocatable output: cstring literals `LC<n>`,
  records of `__cfstring`, `__objc_selrefs` and `__objc_classrefs`
  `l<nnn>`. ld-prime runs one counter over the atoms in address order
  across sections and names a different subset on x86-64; we number
  the literals first. The names carry no meaning, since a later link
  reads the relocations. (3 files)

- **`ltmp` labels on empty sections.** A whole-section object carries
  its `ltmp` labels into a `-r` output as ld-prime does, except a label
  on an empty section, which names nothing and is dropped.

- **Options ld-prime doesn't have.** `--print-dependencies` and a few
  other conveniences are accepted; ld-prime rejects them. They change
  nothing for a command line ld-prime accepts.

- **Bytes that can't match by construction.** `LC_UUID` hashes the
  image and the ad-hoc signature covers the whole file, so they differ
  whenever anything else does, and match when nothing else does.

## Known differences not yet matched

- **Binding to a re-exported library that is also loaded directly.**
  ld-prime binds a symbol to the re-exported library itself whenever
  that library is also loaded in its own right (for example through an
  auto-link option), in any order; we bind to the umbrella if it was
  loaded first. Seen with Swift's `libswift_Builtin_float`, which
  `libswiftDarwin` re-exports. (2 differences in 1 file)
- **`SG_NORELOC` on a segment of only `-sectcreate` data.** ld-prime
  flags a `__DATA` segment whose only section comes from `-sectcreate`;
  we don't. (2 files)
- **Undefined names in `-exported_symbols_list`.** ld-prime rejects a
  list that names a symbol nothing defines; we accept it silently.
- **`__objc_stubs` entry order** differs from ld-prime's.
- **`N_OSO` timestamps of archive members.** ld-prime records the
  member's mtime; we record 0.
- **x86-64 `__stub_helper` size.** ld-prime writes 0x26 bytes where we
  write 0x24.
- **Whole-section Objective-C objects in `-r` output.** ld-prime marks
  `N_NO_DEAD_STRIP` on a narrower set of symbols than every symbol of
  such an object. Compilers always emit Objective-C objects with
  subsections, so this only affects hand-written assembly.
- **`-r` file layout details.** ld-prime pads 32 bytes after the load
  commands, writes `reloff 0` for a section without relocations, and on
  arm64 writes 4 in the personality cell of `__eh_frame` where we copy
  the assembler's bytes (a relocation covers that cell).
