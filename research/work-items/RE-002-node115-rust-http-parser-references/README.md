# RE-002 · Node #115 HTTP URI, method and header parsing

Component: network transport, Rust dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

The existing [byte-window registry](../../byte-windows.json) associates the [root bodies](roots.tsv) with `http` reference builds. This packet resolves the linked destinations of their RIP-relative memory operands whose four-byte displacements are covered by a recorded source relocation. [references.tsv](references.tsv) records source and target instruction bytes, the displacement field and source relocation, the target section and the target dynamic binding at that exact address where present.

| Instruction VA | Opcode | Operand VA | Section | Target binding or bytes |
| --- | --- | --- | --- | --- |
| `0x2e4e912` | `lea` | `0x6184dd` | `.rodata` | file bytes `00000000000000000000000000000000` |
| `0x2e5186e` | `lea` | `0x6193dc` | `.rodata` | file bytes `a2848302ce908302fa8c830262938302` |
| `0x2e548ee` | `call` | `0x64df620` | `.got` | `RELATIVE addend=0x1680cbf` (rustc 1.95.0 _RNvNtCsgEmfK2I1SDS_4core9panicking18panic_bounds_check) |

The denominator is **20 such instruction sites in 4 complete registered bodies**. Destination sections are `.data.rel.ro` (1), `.got` (1), `.rodata` (18). 2 sites land at an address with an ELF dynamic relocation. A RELATIVE addend is a PIE-relative VA, with a registry label only if the addend lands exactly at a registered start. The file preview is at most 16 bytes at the operand address. It does not establish the loaded value, object length, or runtime symbol resolution.

## Reproduction

From the repository root with the authenticated target materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x2e4e8f0 --stop-address=0x2e4ea5b "$node"
objdump -d -M intel --start-address=0x2e51860 --stop-address=0x2e542f0 "$node"
objdump -d -M intel --start-address=0x2e54570 --stop-address=0x2e548f4 "$node"
objdump -d -M intel --start-address=0x2e552f0 --stop-address=0x2e554fd "$node"
readelf -SW "$node"
readelf -rW "$node"
```

For each row, compute the target as the next instruction VA plus the signed little-endian displacement. Compare the reference instruction from its recorded source body at `source_offset + (instruction_va - root_va)`. The root's registry record locates the source relocation that covers the displacement. Read the target section and its file bytes at the computed VA. If a relocation applies at that exact VA, record its symbol or addend.

The local scan verified the target digest and both body hashes using Python 3.12.14 and pyelftools 0.33. Capstone 5.0.9 decoded every complete root. Signed displacement arithmetic agreed at each site, and all non-displacement instruction bytes matched. Changing `4c8d3dc49b7cfd` to `4c8d3dc59b7cfd` at `0x2e4e912` moves the reference from `0x6184dd` to `0x6184de`, which fails the expected-address check. The target was never executed.

This is a static operand map. It leaves runtime reachability, inferred object layouts, and source version selection open. No change to byte coverage or acceptance gates.
