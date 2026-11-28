# RE-009 · Node #115 MessagePack checkpoint writers share one dispatch schema

A single reconstruction of the checkpoint writer's outer MessagePack dispatch can serve both native ABCI state layouts. The two captured writer bodies align across all 756 instructions. They use the same child call targets, literal addresses and relative control flow. Only the 74 recorded state operands after the layout insertion, plus the displacements needed to reach shared code and literals, differ in the raw encodings.

## Target and review context

- Component `storage`, using the Linux x86-64 node #115 artifact at `artifacts/node/115/hl-node`. SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base `2da45cb0a761cff6b478e40421699857d87a94df`. All addresses are original ELF virtual addresses.
- [#6006](https://github.com/lalalune/hyperliquid-source/pull/6006) established the `+0xb70` insertion at state offset `+0x7c0` from setter, engine-step and dispatcher twins. [State snapshot handoff](../RE-017-state-snapshot-handoff-115/) and [ABCI linked commit](../RE-017-abci-linked-commit-115/) map individual writer callers and selected named-map prefix bytes. [Loader checkpoint result](../RE-017-loader-checkpoint-result-115/) identifies the two state-export routers. The question here is whether both MessagePack writer bodies share the same outer schema across their full control flow, including result/error edges and compact and named routes.
- The field-to-root slot mapping is a separate question. The comparison here does not use the root capture routine or infer digest coverage from call order.

## Observations

| Class | Pairs | Comparison |
|---|---:|---|
| Internal jump or conditional edge | 109 | Same opcode and same function-relative target. All targets are instruction starts within their FDE. |
| Direct call | 91 | Same opcode and same absolute executable address, across 62 distinct targets. |
| RIP-relative literal | 41 | Same instruction encoding outside the displacement and same absolute address in `.rodata`. |
| State operand before the insertion | 2 | `[r15 + 0x80]` and `[r15 + 0x670]` are identical. |
| Shifted state operand | 74 | All 74 distinct offsets are at or above `+0x7c0` in the compact layout and exactly `+0xb70` higher in the expanded layout. The last is an immediate add to the state base before passing a child address. |
| Other instruction | 439 | Every instruction byte and decoded operand matches. |

The FDEs are `0x5480950..0x548168c` and `0x5481900..0x548263c`, each `0xd3c` bytes. [The inventory](operands.tsv) lists the raw bytes and class of each aligned pair. A difference in a PC-relative displacement is accepted only if evaluating it produces the same shared address or the same in-function destination relative to the corresponding entry. A difference in a state operand is accepted only for the insertion above. None of the other bytes are masked.

In both bodies, the input pointer arrives in `rsi`, is saved in `r15` at entry offset `+0xe`, then is dereferenced at `+0x71`. The last state-address adjustment at `+0xce5` is `+0x3908` in the compact body and `+0x4478` in the expanded body. The selected compact-layout caller stores `0x01000400` at `0x4e4b8c1` and passes its configuration to the call at `0x4e4b8de`. The selected expanded-layout caller writes the same dword at `0x4e4b461` and passes its configuration at `0x4e4b480`. In both cases the dword starts eight bytes after the passed address, so configuration byte `+0xb` is 1. Both bodies check for nonzero at `+0x1e` and use separate comparisons with exactly 1, including at `+0x149`. The runtime serializer mode and the compact/expanded in-memory state layouts are independent choices.

## Interpretation and limits

The complete outer writer bodies select the same output actions in the same order under matching mode, corresponding field values and equivalent helper results. The native box insertion is a layout distinction at this boundary, so it does not by itself require a second MessagePack grammar. In particular, a checkpoint tool should not select an array encoding merely because its reconstructed state uses the smaller box.

Shared child addresses do not prove equal output for unequal inputs or for children with different reachable state. This comparison does not recover all child encodings, execute the capture, provide a checkpoint fixture, compare actual files, establish a final digest or certify an independently built Rust encoder. No progress gate changes. The next compatibility step is to pair a provenance-backed input and emitted checkpoint and verify the encoded child sequence against these statically established boundaries.

## Reproduce

Run from the repository root with Python 3 and LLVM objdump available. The checker hashes the ELF, reads both FDEs through the repository parser, disassembles each extent, compares the disassembled bytes with the ELF and recomputes the inventory. The offline comparison log records the exact command and tool build. Five in-memory negative controls exercise independent rejection of an altered internal branch, child call, field-literal target, shifted state operand and unchanged opcode.

```sh
PACKET=research/work-items/RE-009-node115-state-writer-layout-pair
PYTHONDONTWRITEBYTECODE=1 python3 "$PACKET/verify.py" --repo . --objdump llvm-objdump
(cd "$PACKET" && shasum -a 256 -c MANIFEST.sha256)
```

The only execution here is the authored Python comparator and static tooling. No Rust build, target execution or hosted CI result is claimed. [Offline log](offline-log.txt)
