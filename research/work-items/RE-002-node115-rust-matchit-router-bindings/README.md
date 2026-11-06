# RE-002 · Node #115 matchit route parameters and insertion errors

Component: Info API, Rust dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

The existing [byte-window registry](../../byte-windows.json) associates the [root bodies](roots.tsv) with `matchit` reference builds. This packet resolves the linked destinations of their RIP-relative memory operands whose four-byte displacements are covered by a recorded source relocation. [references.tsv](references.tsv) records source and target instruction bytes, the displacement field and source relocation, the target section and the target dynamic binding at that exact address where present.

| Instruction VA | Opcode | Operand VA | Section | Target binding or bytes |
| --- | --- | --- | --- | --- |
| `0x47559f9` | `call` | `0x64dfca8` | `.got` | `RELATIVE addend=0x16815e0` into `.text` (rustc 1.95.0 _RNvNtNtCsgEmfK2I1SDS_4core3str8converts13from_utf8_mut) |
| `0x4755a7e` | `call` | `0x64df6a0` | `.got` | `RELATIVE addend=0x1680c30` into `.text` (rustc 1.95.0 _RNvNtCsgEmfK2I1SDS_4core6result13unwrap_failed) |
| `0x4755017` | `lea` | `0x7dfd08` | `.rodata` | file bytes `1f53f7038b53f7035953f7037253f703` |

The denominator is **17 such instruction sites in 2 complete registered bodies**. Destination sections are `.data.rel.ro` (4), `.got` (5), `.rodata` (7), `.text` (1). 7 sites land at an address with an ELF dynamic relocation. A RELATIVE addend is a PIE-relative VA, with a registry label only if the addend lands exactly at a registered start. The file preview is at most 16 bytes at the operand address. It does not establish the loaded value, object length, or runtime symbol resolution. For 7 RELATIVE sites, the table also names the mapped addend section and gives a short file preview when that section is read-only data. These are file addresses and previews before loader effects.

## Reproduction

From the repository root with the authenticated target materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x4755000 --stop-address=0x47550ac "$node"
objdump -d -M intel --start-address=0x47559b0 --stop-address=0x4755ab3 "$node"
readelf -SW "$node"
readelf -rW "$node"
```

For each row, compute the target as the next instruction VA plus the signed little-endian displacement. Compare the reference instruction from its recorded source body at `source_offset + (instruction_va - root_va)`. The root's registry record locates the source relocation that covers the displacement. Read the target section and its file bytes at the computed VA. If a relocation applies at that exact VA, record its symbol or addend.

The local scan verified the target digest and both body hashes using Python 3.12.14 and pyelftools 0.33. Capstone 5.0.9 decoded every complete root. Signed displacement arithmetic agreed at each site, and all non-displacement instruction bytes matched. Changing `ff15a9a2d801` to `ff15a8a2d801` at `0x47559f9` moves the reference from `0x64dfca8` to `0x64dfca7`, which fails the expected-address check. The target was never executed.

This is a static operand map. It leaves runtime reachability, inferred object layouts, and source version selection open. No change to byte coverage or acceptance gates.
