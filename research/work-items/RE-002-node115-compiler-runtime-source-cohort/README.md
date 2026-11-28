# RE-002 · Rebuilding ten Rust runtime functions in node #115

Can independently compiled, licensed Rust sources account for ten previously indexed functions in the captured x86-64 node? The [standard-library census](../RE-002-node115-std-census/README.md) and its byte-window entries identify these extents using a **published** library archive. Here the inputs are the official Rust source releases and the compiler. The sample is selected from reproducible published-library candidates; it does not estimate how often this recipe works across the node.

Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses in the table below are linked ELF virtual addresses. These are existing third-party dependency windows.

## Results

| Rebuilt function | Start VA | Equal bytes / whole function | Linker fields | Rust 1.94.1 control vs. capture |
| --- | ---: | ---: | ---: | --- |
| `udivti3` | `0x63efec0` | 190 / 190 | 0 | 8 bytes longer |
| `floattidf` | `0x63f0160` | 168 / 168 | 0 | Equal |
| `trunc` | `0x63eff80` | 85 / 85 | 0 | Equal |
| Decimal rounding | `0x167e8d0` | 249 / 249 | 0 | 12 bytes shorter |
| `CStr::from_bytes_with_nul` | `0x167e030` | 273 / 273 | 0 | Equal |
| Aligned `memchr` | `0x16818b0` | 215 / 215 | 0 | Equal |
| `powidf2` | `0x63f0080` | 62 / 70 | 2 | 20 bytes longer |
| Lemire float conversion | `0x167c730` | 373 / 377 | 1 | 8 bytes longer |
| UTF-8 character count | `0x1681020` | 1,445 / 1,464 | 5 | 19 bytes longer |
| Unicode grapheme-extend lookup | `0x1682bf0` | 241 / 249 | 2 | Equal outside the two linker fields |

Two clean Rust 1.95.0 builds produced identical function bodies. Six functions match the linked executable byte for byte. Across all ten, 3,301 of 3,340 positions are equal before accounting for linking. The four remaining functions have ten 4-byte displacement fields, and all 3,300 positions outside those fields match. One byte inside a field happens to match as well.

Nine PC-relative displacements reference read-only data directly. The Lemire conversion uses a GOT entry whose dynamic relocation points to the 10,416-byte power-of-five table. The verifier resolves all ten references in the captured ELF and compares the size and SHA-256 of each destination with the source objects. They identify seven distinct data values. The alternate compiler output demonstrates that five of the ten selected functions cannot distinguish the two tested Rust releases under this recipe.

## Reproduce

From this packet directory, install Python 3.12+, GNU binutils and the two Rust toolchains. The build reuses the previously [reviewed release-source build](../RE-002-node115-umodti3-source-build/build.py). The probe targets `x86_64-unknown-linux-gnu`, uses 256 release codegen units and rebuilds `core` and `compiler_builtins`. Source archives are SHA-256 pinned, toolchains are commit pinned, and the Cargo dependencies are locked. Provisioning requires network access. The build runs Cargo offline and only reads the new object archives; it never invokes the captured node.

```sh
rustup toolchain install 1.95.0 1.94.1 --profile minimal
workdir=$(mktemp -d)
python3 build.py provision --cache "$workdir/cache"
python3 build.py run --cache "$workdir/cache" --output "$workdir/result"
python3 -B verify.py "$workdir/result"
```

Use `--binutils-dir` when the GNU tools are outside PATH. The per-build records in [build-results.json](build-results.json) name the archive, object, symbol, body hash and relocations. The [source-side data measurements](source-referents.json) record the size and hash of the data symbol referenced by each relocation. Path-sensitive hashes of entire archives or objects may differ across environments. Compare complete function bodies and actual relocation entries.

For a quick replay against the retained source bytes, run `python3 -B verify.py` here with the repository's Git LFS capture installed. From the repository root, `make fde-index` independently recovers an unwind range with the listed start and end for each of the ten entries.

## Rights and scope

The two packed byte files contain functions extracted from locally built public Rust sources. The core material uses the [Rust MIT terms](rust-LICENSE-MIT) with the [upstream copyright notice](rust-COPYRIGHT). Rust's core `memchr` implementation also credits Andrew Gallant, bluss and Nicolas Koch (2015). The distribution includes the [compiler-builtins license](compiler-builtins-LICENSE.txt) and the [libm license and bundled notices](libm-LICENSE.txt) for its math code. See the [Rust 1.95.0 source](https://github.com/rust-lang/rust/tree/59807616e1fa2540724bfbac14d7976d7e4a3860/library) and [Rust 1.94.1 control source](https://github.com/rust-lang/rust/tree/e408947bfd200af42db322daf0fadfe7e26d3bd1/library).

This experiment does not recover the original complete node build invocation, execute the captured program, or advance any first-party or full-component gate. Each prior published-archive candidate remains in the catalogue as provenance for the same window.
