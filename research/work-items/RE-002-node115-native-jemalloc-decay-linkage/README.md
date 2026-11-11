# RE-002 · Node #115 jemalloc dirty-page decay scheduling

Component: foundation utilities, native dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

This packet resolves concrete outgoing direct transfers in the tikv-jemalloc-sys windows listed in [roots.tsv](roots.tsv). The earlier [byte-window registry](../../byte-windows.json) establishes the source-window attribution and records the relocation masks. [linkage.tsv](linkage.tsv) connects those records to the actual linked instruction bytes and destinations.

| Reference root | Instruction VA | Transfer | Destination VA | Destination attribution |
| --- | --- | --- | --- | --- |
| `_rjem_je_decay_reinit` | `0x63a9593` | `call` | `0x63a9440` | `_rjem_je_decay_deadline_init` |
| `_rjem_je_decay_reinit` | `0x63a9584` | `call` | `0x63bfbf0` | `unattributed` |
| `_rjem_je_decay_maybe_advance_epoch` | `0x63a984e` | `call` | `0x63f0a70` | `PLT memmove` |

The denominator is **19 off-window direct transfer sites in 4 registered bodies**. 19 instruction sites have a four-byte displacement covered by a recorded source relocation. 5 sites have destination labels from an exact registered function start or an ELF PLT relocation. The remainder retain their addresses without a symbol claim.

## Reproduction

From the repository root with the target materialized, verify the full digest and decode the recorded ranges:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x6360e90 --stop-address=0x6360eb4 "$node"
objdump -d -M intel --start-address=0x63a9540 --stop-address=0x63a95d9 "$node"
objdump -d -M intel --start-address=0x63a9750 --stop-address=0x63a99ed "$node"
objdump -d -M intel --start-address=0x63a99f0 --stop-address=0x63aa3a0 "$node"
objdump -d -j .plt "$node"
readelf -rW "$node"
```

For each direct call or unconditional jump out of the window, add the signed displacement to the next instruction VA. Compare the reference bytes by reading the recorded source path at `source_offset + (site_va - root_va)`. The registry's relocation pointer identifies which source displacement was masked and the type and addend in the table. For a PLT entry, the RIP-relative jump identifies the GOT slot and `.rela.plt` identifies its dynamic symbol.

The local scan used Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. It verified the source and target body hashes, decoded each full root interval and checked the signed displacement independently of the disassembler. The negative control changes `e8a8feffff` to `e8a9feffff` at `0x63a9593`, producing `0x63a9441` instead of `0x63a9440`. The artifact was read only.

These are static instruction sites. Indirect calls, conditional branches, and runtime paths are outside the scope. Source attribution comes from the existing registry, with any ambiguities retained in the table. This packet does not change byte coverage or acceptance gates.
