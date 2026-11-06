# RE-002 · Node #115 zlib inflate decoding and window maintenance

Component: foundation utilities, native dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

This packet resolves concrete outgoing direct transfers in the libz-sys windows listed in [roots.tsv](roots.tsv). The earlier [byte-window registry](../../byte-windows.json) establishes the source-window attribution and records the relocation masks. [linkage.tsv](linkage.tsv) connects those records to the actual linked instruction bytes and destinations.

| Reference root | Instruction VA | Transfer | Destination VA | Destination attribution |
| --- | --- | --- | --- | --- |
| `inflateSetDictionary` | `0x6307d7b` | `call` | `0x63055d0` | `updatewindow` |
| `inflate` | `0x6305d6d` | `call` | `0x6307df0` | `inflate_fast` |
| `inflate` | `0x63074f1` | `call` | `0x6309090` | `inflate_table` |
| `inflateInit2_` | `0x63058f0` | `call` | `0x6305710` | `inflateReset` |

The denominator is **32 off-window direct transfer sites in 5 registered bodies**. 32 instruction sites have a four-byte displacement covered by a recorded source relocation. 14 sites have destination labels from an exact registered function start or an ELF PLT relocation. The remainder retain their addresses without a symbol claim.

## Reproduction

From the repository root with the target materialized, verify the full digest and decode the recorded ranges:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x6307ce0 --stop-address=0x6307de2 "$node"
objdump -d -M intel --start-address=0x63055d0 --stop-address=0x630570f "$node"
objdump -d -M intel --start-address=0x6305810 --stop-address=0x630593e "$node"
objdump -d -M intel --start-address=0x6305940 --stop-address=0x6307c34 "$node"
objdump -d -M intel --start-address=0x6309090 --stop-address=0x6309e97 "$node"
objdump -d -j .plt "$node"
readelf -rW "$node"
```

For each direct call or unconditional jump out of the window, add the signed displacement to the next instruction VA. Compare the reference bytes by reading the recorded source path at `source_offset + (site_va - root_va)`. The registry's relocation pointer identifies which source displacement was masked and the type and addend in the table. For a PLT entry, the RIP-relative jump identifies the GOT slot and `.rela.plt` identifies its dynamic symbol.

The local scan used Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. It verified the source and target body hashes, decoded each full root interval and checked the signed displacement independently of the disassembler. The negative control changes `e850d8ffff` to `e851d8ffff` at `0x6307d7b`, producing `0x63055d1` instead of `0x63055d0`. The artifact was read only.

These are static instruction sites. Indirect calls, conditional branches, and runtime paths are outside the scope. Source attribution comes from the existing registry, with any ambiguities retained in the table. This packet does not change byte coverage or acceptance gates.
