# RE-002 · Node #115 REVM BN254 precompile dispatch

Component: HyperEVM execution, Rust dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

The existing [byte-window registry](../../byte-windows.json) associates the [root bodies](roots.tsv) with `revm-precompile` reference builds. This packet resolves the linked destinations of their RIP-relative memory operands whose four-byte displacements are covered by a recorded source relocation. [references.tsv](references.tsv) records source and target instruction bytes, the displacement field and source relocation, the target section and the target dynamic binding at that exact address where present.

| Instruction VA | Opcode | Operand VA | Section | Target binding or bytes |
| --- | --- | --- | --- | --- |
| `0x5c15bba` | `call` | `0x64eaec0` | `.got` | `RELATIVE addend=0x5c16080` |
| `0x5c15c5a` | `call` | `0x64eaec0` | `.got` | `RELATIVE addend=0x5c16080` |
| `0x5beb121` | `call` | `0x64df570` | `.got` | `RELATIVE addend=0x16817e0` (rustc 1.95.0 _RNvNtNtCsgEmfK2I1SDS_4core5slice5index16slice_index_fail) |

The denominator is **39 such instruction sites in 10 complete registered bodies**. Destination sections are `.data.rel.ro` (14), `.got` (15), `.rodata` (10). 29 sites land at an address with an ELF dynamic relocation. A RELATIVE addend is a PIE-relative VA, with a registry label only if the addend lands exactly at a registered start. The file preview is at most 16 bytes at the operand address. It does not establish the loaded value, object length, or runtime symbol resolution.

## Reproduction

From the repository root with the authenticated target materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x5beaf10 --stop-address=0x5beb141 "$node"
objdump -d -M intel --start-address=0x5beb150 --stop-address=0x5beb3c6 "$node"
objdump -d -M intel --start-address=0x5beb3d0 --stop-address=0x5beb600 "$node"
objdump -d -M intel --start-address=0x5c15ba0 --stop-address=0x5c15c3a "$node"
objdump -d -M intel --start-address=0x5c15c40 --stop-address=0x5c15cda "$node"
objdump -d -M intel --start-address=0x5c09750 --stop-address=0x5c097ea "$node"
objdump -d -M intel --start-address=0x5c097f0 --stop-address=0x5c0988a "$node"
objdump -d -M intel --start-address=0x5c15ce0 --stop-address=0x5c15d80 "$node"
objdump -d -M intel --start-address=0x5c15d80 --stop-address=0x5c15e20 "$node"
objdump -d -M intel --start-address=0x5beb600 --stop-address=0x5bebab1 "$node"
readelf -SW "$node"
readelf -rW "$node"
```

For each row, compute the target as the next instruction VA plus the signed little-endian displacement. Compare the reference instruction from its recorded source body at `source_offset + (instruction_va - root_va)`. The root's registry record locates the source relocation that covers the displacement. Read the target section and its file bytes at the computed VA. If a relocation applies at that exact VA, record its symbol or addend.

The local scan verified the target digest and both body hashes using Python 3.12.14 and pyelftools 0.33. Capstone 5.0.9 decoded every complete root. Signed displacement arithmetic agreed at each site, and all non-displacement instruction bytes matched. Changing `ff1500538d00` to `ff1501538d00` at `0x5c15bba` moves the reference from `0x64eaec0` to `0x64eaec1`, which fails the expected-address check. The target was never executed.

This is a static operand map. It leaves runtime reachability, inferred object layouts, and source version selection open. No change to byte coverage or acceptance gates.
