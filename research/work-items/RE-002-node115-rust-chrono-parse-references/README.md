# RE-002 · Node #115 Chrono calendar and RFC3339 parsing

Component: foundation utilities, Rust dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

The existing [byte-window registry](../../byte-windows.json) associates the [root bodies](roots.tsv) with `chrono` reference builds. This packet resolves the linked destinations of their RIP-relative memory operands whose four-byte displacements are covered by a recorded source relocation. [references.tsv](references.tsv) records source and target instruction bytes, the displacement field and source relocation, the target section and the target dynamic binding at that exact address where present.

| Instruction VA | Opcode | Operand VA | Section | Target binding or bytes |
| --- | --- | --- | --- | --- |
| `0x162568d` | `call` | `0x64e1b10` | `.got` | `RELATIVE addend=0x1624fb0` (one of 2 identical bodies, e.g. _ZN6chrono6format4scan12short_month017hbcb844172381b80cE) |
| `0x16251f3` | `lea` | `0x6404fc0` | `.data.rel.ro` | `RELATIVE addend=0x443ce4` |
| `0x1621744` | `lea` | `0x6404630` | `.data.rel.ro` | `RELATIVE addend=0x43287f` |

The denominator is **27 such instruction sites in 5 complete registered bodies**. Destination sections are `.data.rel.ro` (14), `.got` (10), `.rodata` (3). 22 sites land at an address with an ELF dynamic relocation. A RELATIVE addend is a PIE-relative VA, with a registry label only if the addend lands exactly at a registered start. The file preview is at most 16 bytes at the operand address. It does not establish the loaded value, object length, or runtime symbol resolution.

## Reproduction

From the repository root with the authenticated target materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x161f900 --stop-address=0x161fa20 "$node"
objdump -d -M intel --start-address=0x1621730 --stop-address=0x16218fa "$node"
objdump -d -M intel --start-address=0x1624fb0 --stop-address=0x16250f3 "$node"
objdump -d -M intel --start-address=0x1625100 --stop-address=0x162520b "$node"
objdump -d -M intel --start-address=0x1625680 --stop-address=0x1625784 "$node"
readelf -SW "$node"
readelf -rW "$node"
```

For each row, compute the target as the next instruction VA plus the signed little-endian displacement. Compare the reference instruction from its recorded source body at `source_offset + (instruction_va - root_va)`. The root's registry record locates the source relocation that covers the displacement. Read the target section and its file bytes at the computed VA. If a relocation applies at that exact VA, record its symbol or addend.

The local scan verified the target digest and both body hashes using Python 3.12.14 and pyelftools 0.33. Capstone 5.0.9 decoded every complete root. Signed displacement arithmetic agreed at each site, and all non-displacement instruction bytes matched. Changing `ff157dc4eb04` to `ff157cc4eb04` at `0x162568d` moves the reference from `0x64e1b10` to `0x64e1b0f`, which fails the expected-address check. The target was never executed.

This is a static operand map. It leaves runtime reachability, inferred object layouts, and source version selection open. No change to byte coverage or acceptance gates.
