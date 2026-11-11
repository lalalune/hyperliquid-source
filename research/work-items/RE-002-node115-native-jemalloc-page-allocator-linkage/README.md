# RE-002 · Node #115 jemalloc page allocator shard lifecycle

Component: foundation utilities, native dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

This packet resolves concrete outgoing direct transfers in the tikv-jemalloc-sys windows listed in [roots.tsv](roots.tsv). The earlier [byte-window registry](../../byte-windows.json) establishes the source-window attribution and records the relocation masks. [linkage.tsv](linkage.tsv) connects those records to the actual linked instruction bytes and destinations.

| Reference root | Instruction VA | Transfer | Destination VA | Destination attribution |
| --- | --- | --- | --- | --- |
| `_rjem_je_pa_shard_init` | `0x63bfe7f` | `call` | `0x63c1600` | `_rjem_je_pac_init` |
| `_rjem_je_pa_shard_enable_hpa` | `0x63bff41` | `call` | `0x63b8fe0` | `_rjem_je_hpa_shard_init` |
| `_rjem_je_pa_alloc` | `0x63c0148` | `call` | `0x63ae6e0` | `_rjem_je_emap_register_interior` |
| `_rjem_je_pa_dalloc` | `0x63c03dd` | `call` | `0x63aed40` | `_rjem_je_emap_deregister_interior` |

The denominator is **16 off-window direct transfer sites in 9 registered bodies**. 16 instruction sites have a four-byte displacement covered by a recorded source relocation. 11 sites have destination labels from an exact registered function start or an ELF PLT relocation. The remainder retain their addresses without a symbol claim.

## Reproduction

From the repository root with the target materialized, verify the full digest and decode the recorded ranges:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x63bfdf0 --stop-address=0x63bfef9 "$node"
objdump -d -M intel --start-address=0x63bff00 --stop-address=0x63bff93 "$node"
objdump -d -M intel --start-address=0x63bffa0 --stop-address=0x63bffdd "$node"
objdump -d -M intel --start-address=0x63bffe0 --stop-address=0x63c0004 "$node"
objdump -d -M intel --start-address=0x63c0010 --stop-address=0x63c0064 "$node"
objdump -d -M intel --start-address=0x63c0070 --stop-address=0x63c01af "$node"
objdump -d -M intel --start-address=0x63c01b0 --stop-address=0x63c0272 "$node"
objdump -d -M intel --start-address=0x63c0280 --stop-address=0x63c0336 "$node"
objdump -d -M intel --start-address=0x63c0340 --stop-address=0x63c03e8 "$node"
objdump -d -j .plt "$node"
readelf -rW "$node"
```

For each direct call or unconditional jump out of the window, add the signed displacement to the next instruction VA. Compare the reference bytes by reading the recorded source path at `source_offset + (site_va - root_va)`. The registry's relocation pointer identifies which source displacement was masked and the type and addend in the table. For a PLT entry, the RIP-relative jump identifies the GOT slot and `.rela.plt` identifies its dynamic symbol.

The local scan used Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. It verified the source and target body hashes, decoded each full root interval and checked the signed displacement independently of the disassembler. The negative control changes `e87c170000` to `e87d170000` at `0x63bfe7f`, producing `0x63c1601` instead of `0x63c1600`. The artifact was read only.

These are static instruction sites. Indirect calls, conditional branches, and runtime paths are outside the scope. Source attribution comes from the existing registry, with any ambiguities retained in the table. This packet does not change byte coverage or acceptance gates.
