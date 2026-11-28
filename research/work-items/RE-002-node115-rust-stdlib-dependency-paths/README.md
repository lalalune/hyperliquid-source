# RE-002 · trace node #115's Rust standard-library dependency paths to shipped ELF members

All 12 source paths under `/rust/deps/` in the pinned Linux node's allocated data occur in ELF object sections of the official Rust 1.95.0 Linux standard-library distribution. Rust 1.94.1 matches nine full paths. Its three paths for rustc-demangle use 0.1.26 where the node and 1.95.0 use 0.1.27.

The node's RE-002 build-provenance packet already names the five packages. The std census compares function bodies from libcore, compiler-builtins, liballoc and libstd. Here the unit of comparison is the source pathname as shipped in a loadable object section, followed for the discriminating package by its data relocations. The two official distributions each contain 27 rlibs and 346 ELF64 little-endian .o members. The replay skips rustc metadata, DWARF and executable sections.

| Package | Path count in target | Rust 1.95.0 library/Cargo.lock | Rust 1.94.1 | Shortest shown library lock route from std |
| --- | ---: | --- | --- | --- |
| addr2line | 3 | 0.25.1 | 0.25.1 | std → addr2line |
| gimli | 3 | 0.32.3 | 0.32.3 | std → addr2line → gimli |
| hashbrown | 1 | 0.16.1 | 0.16.1 | std → hashbrown |
| miniz_oxide | 2 | 0.8.9 | 0.8.9 | std → miniz_oxide |
| rustc-demangle | 3 | 0.1.27 | 0.1.26 | std → rustc-demangle |

Archive ownership adds information beyond the package name in a path. In both releases, addr2line's function.rs and unit.rs and gimli's read/index.rs and read/line.rs occur in libstd. Their other observed files occur in libaddr2line and libgimli respectively. Each of the three demangler paths occurs in a .rodata.str1.1 section of the distributed librustc_demangle object. [evidence.json](evidence.json) records archive and member names, member digests, input component digests, object offsets, section-relative offsets, library lock digests and registry package checksums.

## Comparing source locations without the version label

For the three demangler paths, the target has 39 distinct location-shaped records in .data.rel.ro. Each begins with a symbol-index-zero R_X86_64_RELATIVE pointer to a path, followed by the matching byte length and two 32-bit integers interpreted as line and column. The independently built distribution uses R_X86_64_64 relocations in 24-byte data objects, resolved through the object symbol table. Both distributions supply 40 distinct tuples.

Even after removing the whole version prefix, Rust 1.95.0 matches **39/39** target tuples and 1.94.1 matches **38/39**. At target VA 0x64c18d0, the tuple is src/v0.rs line 1265, column 45. Version 1.94.1 carries line 1261, column 45 instead. As a source-level check, the two crate archives with the checksums recorded under their library locks contain the same `basic_type(ty_tag).unwrap()` statement on those respective lines. Conversely, src/legacy.rs line 116, column 25 appears in both release objects and in none of the 39 linked records. The output retains these negative controls.

This establishes consistency with the distributed 1.95.0 standard library for the observed paths and records, including one location that separates these two releases. The library's own Cargo.lock supplies an upstream explanation for these versions. The application's Cargo.lock, linked object identities, compiler flags, other releases with identical inputs and the reason one source location is absent remain open.

## Replay

Component foundation, task RE-002. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The replay authenticates the capture and four compressed components before analysis. File digests come from the dated official [1.95.0 manifest](https://static.rust-lang.org/dist/2026-04-16/channel-rust-1.95.0.toml) and [1.94.1 manifest](https://static.rust-lang.org/dist/2026-03-26/channel-rust-1.94.1.toml). The stored JSON contains offsets and hashes, and redistributes no Rust binaries.

From the repository root with the capture materialized, fetch the four components into a disposable directory. Use Python 3.11+ (verified with 3.14.3). The scanner uses the existing std census ar reader and repository ELF reader, and never executes the capture or release binaries.

```sh
cache=$(mktemp -d)
for release in 1.95.0 1.94.1; do
  case "$release" in
    1.95.0) date=2026-04-16 ;;
    1.94.1) date=2026-03-26 ;;
  esac
  base="https://static.rust-lang.org/dist/$date"
  curl -fsSL "$base/rust-src-$release.tar.xz" -o "$cache/rust-src-$release.tar.xz" || exit 1
  curl -fsSL "$base/rust-std-$release-x86_64-unknown-linux-gnu.tar.xz" -o "$cache/rust-std-$release.tar.xz" || exit 1
done
packet=research/work-items/RE-002-node115-rust-stdlib-dependency-paths
python3 -B "$packet/replay.py" "$cache" > "$cache/replay.json"
diff -u "$packet/evidence.json" "$cache/replay.json"
```
