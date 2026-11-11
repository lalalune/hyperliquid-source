# RE-002 · Node #115 bzip2 block sorting and stream compression

Component: foundation utilities, native dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

This packet resolves concrete outgoing direct transfers in the bzip2-sys windows listed in [roots.tsv](roots.tsv). The earlier [byte-window registry](../../byte-windows.json) establishes the source-window attribution and records the relocation masks. [linkage.tsv](linkage.tsv) connects those records to the actual linked instruction bytes and destinations.

| Reference root | Instruction VA | Transfer | Destination VA | Destination attribution |
| --- | --- | --- | --- | --- |
| `BZ2_blockSort` | `0x6317e9c` | `call` | `0x6315ee0` | `mainSort.isra.0` |
| `BZ2_blockSort` | `0x6317efe` | `call` | `0x63152c0` | `fallbackSort.isra.0` |
| `BZ2_compressBlock` | `0x63107ea` | `call` | `0x6317f40` | `BZ2_hbMakeCodeLengths` |
| `handle_compress.isra.0` | `0x630cb57` | `call` | `0x630e460` | `BZ2_compressBlock` |

The denominator is **26 off-window direct transfer sites in 4 registered bodies**. 26 instruction sites have a four-byte displacement covered by a recorded source relocation. 19 sites have destination labels from an exact registered function start or an ELF PLT relocation. The remainder retain their addresses without a symbol claim.

## Reproduction

From the repository root with the target materialized, verify the full digest and decode the recorded ranges:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x6317e10 --stop-address=0x6317f31 "$node"
objdump -d -M intel --start-address=0x630e460 --stop-address=0x63152bf "$node"
objdump -d -M intel --start-address=0x630c6f0 --stop-address=0x630cbcb "$node"
objdump -d -M intel --start-address=0x630ce10 --stop-address=0x630cffa "$node"
objdump -d -j .plt "$node"
readelf -rW "$node"
```

For each direct call or unconditional jump out of the window, add the signed displacement to the next instruction VA. Compare the reference bytes by reading the recorded source path at `source_offset + (site_va - root_va)`. The registry's relocation pointer identifies which source displacement was masked and the type and addend in the table. For a PLT entry, the RIP-relative jump identifies the GOT slot and `.rela.plt` identifies its dynamic symbol.

The local scan used Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. It verified the source and target body hashes, decoded each full root interval and checked the signed displacement independently of the disassembler. The negative control changes `e83fe0ffff` to `e83ee0ffff` at `0x6317e9c`, producing `0x6315edf` instead of `0x6315ee0`. The artifact was read only.

These are static instruction sites. Indirect calls, conditional branches, and runtime paths are outside the scope. Source attribution comes from the existing registry, with any ambiguities retained in the table. This packet does not change byte coverage or acceptance gates.
