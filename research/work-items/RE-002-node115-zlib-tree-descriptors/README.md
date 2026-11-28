# RE-002 · zlib static Huffman tree descriptors in node #115

The three PC-relative fields in zlib's registered `_tr_init` window lead to the literal/length, distance and bit-length tree descriptors in ELF `.data.rel.ro`. Five dynamic relocations bind their array pointers. The encoder's code-length permutation has two identical copies in `.rodata`; the linked `_tr_flush_block` operand selects one.

| Source descriptor | Target VA | Tree | Extra-bit table | Extra base, elements, maximum bits |
| --- | --- | --- | --- | --- |
| static_l_desc | 0x64da240 | static_ltree | extra_lbits | 257, 286, 15 |
| static_d_desc | 0x64da220 | static_dtree | extra_dbits | 0, 30, 15 |
| static_bl_desc | 0x64da200 | NULL | extra_blbits | 0, 19, 7 |

## Evidence

Component foundation, task RE-002. Target Linux x86-64 node #115 (105,896,032 bytes), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. The source archive is libz-sys 1.1.31, SHA-256 `ff20308ecabd635a2dc1dd5834a86c462cca20efba1d5d3ddab1f8aea3455cb2`, as recorded in the vendor census's gcc-rocksdb0210/Cargo.lock. Its bundled zlib 1.3.2 defines these fields and initializers in src/zlib/trees.c and trees.h under src/zlib/LICENSE.

The existing vendor census verifies both complete function bodies with relocation masks. Its data fields have numeric types and offsets. The deflate/inflate linkage packets cover direct transfers. To recover the table ownership, the replay takes every PC32 field from `_tr_init` (3/3), adds its signed displacement to the address after the field and verifies the descriptor there. For each descriptor, the two raw pointer slots are zero in the ELF file. Each of five non-null pointers is supplied by one symbol-index-zero R_X86_64_RELATIVE addend in .rela.dyn. The remaining slot in static_bl_desc has zero raw value and no relocation. The three int fields beginning at byte 16 match the C initializer. The five referenced complete arrays each have one occurrence in .rodata.

The 19-byte bit-length ordering permutation matches both 0x7dffa4 and 0x987e80. Of the 12 PC32 fields in `_tr_flush_block`, the one at 0x630bf9f reaches one of these copies. Its signed displacement bytes are `ddbe67fa`, selecting 0x987e80. The earlier copy would require `01404dfa`. The earlier copy's owning component remains open. [bindings.tsv](bindings.tsv) records both candidates and the whole-array digests; all addresses are linked ELF virtual addresses.

Three independent controls exercised the descriptor decoder after the outer ELF identity check. Redirecting the distance descriptor's second relocation to extra_lbits was rejected. Adding a relocation to the bit-length descriptor's literal zero slot was rejected. Changing the literal/length descriptor's extra-base scalar from 257 to 256 was rejected. The capture stayed on disk unmodified.

These observations identify the descriptors and the encoder's selected copy, with no inference about global zlib build options, runtime block choices, or versions with identical constant values.

## Replay

From the repository root with the pinned capture available, download the public source archive once. Python 3.14.3 with its standard library and repository ELF helpers produced the recorded output. The replay reads both archives entirely offline and never launches the captured executable.

```sh
packet=research/work-items/RE-002-node115-zlib-tree-descriptors
crate=libz-sys-1.1.31.crate
curl -fsSL 'https://static.crates.io/crates/libz-sys/libz-sys-1.1.31.crate' -o "$crate"
python3 -B "$packet/replay.py" "$crate" > /tmp/zlib-node115-bindings.tsv
diff -u "$packet/bindings.tsv" /tmp/zlib-node115-bindings.tsv
```
