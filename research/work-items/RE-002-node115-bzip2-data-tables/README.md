# RE-002 · libbzip2 CRC and randomized-block tables in node #115

All 20 MOV-to-LEA relocation fields recorded for bzip2-sys in the vendor census resolve to two adjacent .data arrays. The full little-endian initializers in public libbzip2 1.0.8 occur exactly once each in the authenticated Linux x86-64 node ELF.

| Public C symbol | Target virtual address | Full size | References |
| --- | --- | ---: | ---: |
| BZ2_crc32Table | 0x64feea0 | 256 × 4 = 1,024 bytes | 8 |
| BZ2_rNums | 0x64ff2a0 | 512 × 4 = 2,048 bytes | 12 |

The earlier vendor census established 18 bzip2-sys function bodies under relocation masks. The existing encode/decode linkage packets identified direct transfers between functions. Their remaining data operands matter for reconstructing which constants the encoder and decoder share. The public source uses the first array in its block CRC update and the second when undoing randomization for a block whose randomized flag is set. The references here are static. Whether archived inputs actually exercise randomization remains unknown.

## Evidence

Component foundation, task RE-002, base `2da45cb0a761cff6b478e40421699857d87a94df`. The SHA-256 of the historical node is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The bzip2-sys 0.1.13+1.0.8 source archive has SHA-256 `225bff33b2141874fe80d71e07d6eec4f85c5c216453dd96388240f96e1acc14`, also pinned by the vendor census's `gcc-rocksdb0210/Cargo.lock`. Inside the archive, `bzip2-1.0.8/crctable.c` and `randtable.c` define the arrays. The bundled C sources carry Julian Seward's libbzip2 license in `bzip2-1.0.8/LICENSE`.

[bindings.tsv](bindings.tsv) contains the original and linked instruction bytes, virtual address of each four-byte displacement, table identities and whole-array SHA-256 values. The denominator is all 209 recorded relocation fields in the 18 bzip2-sys function bodies. Exactly 20 have the census's MOV-to-LEA relaxation. All 20 independently recovered destinations match array starts. Four functions supply them, namely `add_pair_to_block`, `handle_compress.isra.0`, `BZ2_bzDecompress`, and `BZ2_decompress`.

For example, the field at `0x630c59b` belongs to an instruction whose unlinked encoding is `4c8b0500000000`. Its linked encoding is `4c8d0501291f00`. Adding its signed displacement to the following instruction address gives `0x630c59f + 0x1f2901 = 0x64feea0`. Changing the first displacement byte from `01` to `00` gives `0x64fee9f`, one byte before the CRC table. Flipping the last source CRC-table byte yields zero complete matches in the ELF. Both negative controls were checked.

The table identities establish data linkage for these fields. They leave the original build configuration, other masked fields, runtime coverage and component acceptance open. Public versions that carry identical table data cannot be discriminated by these bytes.

## Reproduction

From the repository root with the pinned capture materialized, obtain the source crate once and run the replay locally. Python 3.14.3 was used, with the standard library and the repository's ELF and relocation comparators. The replay authenticates the archive, census, target and both sides of every function window. It reads the two named source members without extracting or executing them.

```sh
packet=research/work-items/RE-002-node115-bzip2-data-tables
crate=bzip2-sys-0.1.13+1.0.8.crate
curl -fsSL 'https://static.crates.io/crates/bzip2-sys/bzip2-sys-0.1.13%2B1.0.8.crate' -o "$crate"
python3 -B "$packet/replay.py" "$crate" > /tmp/bzip2-node115-bindings.tsv
diff -u "$packet/bindings.tsv" /tmp/bzip2-node115-bindings.tsv
```
