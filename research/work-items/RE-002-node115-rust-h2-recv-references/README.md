# RE-002 · Node #115 h2 stream receive queues

Component: network transport, Rust dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

The existing [byte-window registry](../../byte-windows.json) associates the [root bodies](roots.tsv) with `h2` reference builds. This packet resolves the linked destinations of their RIP-relative memory operands whose four-byte displacements are covered by a recorded source relocation. [references.tsv](references.tsv) records source and target instruction bytes, the displacement field and source relocation, the target section and the target dynamic binding at that exact address where present.

| Instruction VA | Opcode | Operand VA | Section | Target binding or bytes |
| --- | --- | --- | --- | --- |
| `0x1780a31` | `call` | `0x64e0718` | `.got` | `RELATIVE addend=0x1796580` (one of 5 identical bodies, e.g. _ZN2h25proto7streams5state5State16ensure_recv_open17hf734ced323e8bd11E) |
| `0x17837a7` | `call` | `0x64e0718` | `.got` | `RELATIVE addend=0x1796580` (one of 5 identical bodies, e.g. _ZN2h25proto7streams5state5State16ensure_recv_open17hf734ced323e8bd11E) |
| `0x17803a0` | `call` | `0x64df508` | `.got` | `type=6 symbol=memcpy addend=0` |

The denominator is **23 such instruction sites in 4 complete registered bodies**. Destination sections are `.data.rel.ro` (5), `.got` (12), `.rodata` (4), `.text` (2). 17 sites land at an address with an ELF dynamic relocation. A RELATIVE addend is a PIE-relative VA, with a registry label only if the addend lands exactly at a registered start. The file preview is at most 16 bytes at the operand address. It does not establish the loaded value, object length, or runtime symbol resolution.

## Reproduction

From the repository root with the authenticated target materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x177f0a0 --stop-address=0x177f1ea "$node"
objdump -d -M intel --start-address=0x1780330 --stop-address=0x1780449 "$node"
objdump -d -M intel --start-address=0x17809e0 --stop-address=0x1780bd3 "$node"
objdump -d -M intel --start-address=0x1783750 --stop-address=0x178394c "$node"
readelf -SW "$node"
readelf -rW "$node"
```

For each row, compute the target as the next instruction VA plus the signed little-endian displacement. Compare the reference instruction from its recorded source body at `source_offset + (instruction_va - root_va)`. The root's registry record locates the source relocation that covers the displacement. Read the target section and its file bytes at the computed VA. If a relocation applies at that exact VA, record its symbol or addend.

The local scan verified the target digest and both body hashes using Python 3.12.14 and pyelftools 0.33. Capstone 5.0.9 decoded every complete root. Signed displacement arithmetic agreed at each site, and all non-displacement instruction bytes matched. Changing `ff15e1fcd504` to `ff15e0fcd504` at `0x1780a31` moves the reference from `0x64e0718` to `0x64e0717`, which fails the expected-address check. The target was never executed.

This is a static operand map. It leaves runtime reachability, inferred object layouts, and source version selection open. No change to byte coverage or acceptance gates.
