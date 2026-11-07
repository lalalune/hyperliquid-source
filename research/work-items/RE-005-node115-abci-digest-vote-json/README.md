# RE-005 · Node #115 ABCI digest vote JSON field projection

- Scope: selected writer paths for the `VoteAbciDigestAction` payload. This identifies the fields exposed by a candidate reference-digest source.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external reference implementation was used.

## Observations

The two compact bodies at `0x29abdc0` and `0x5924ea0` pass the 20-byte action name and declare three fields. In both, the selected path calls the named-field writers in the same order.

| Field | Source | First compact body | Second compact body |
| --- | --- | --- | --- |
| `height` | payload `+0x20` | `0x29abe33` | `0x5924f13` |
| `abciDigest` | payload base | `0x29abe5c` | `0x5924f3c` |
| `signature` | payload `+0x28` | `0x29abe85` | `0x5924f65` |

For the first compact body, initial result tag 2 returns its accompanying qword. An intermediate tag 1 goes to the shared helper with a stack qword of 10. A nonzero field-helper result goes to the epilogue before any later field. The selected closing-brace path calls its writer and clears RAX before returning. The second compact copy exhibits the same selected field projections and closing-brace pattern, with its own helper targets.

The inlined writer at `0x29ab7b0` uses the same field order. Its selected digest path passes payload base, width `0x20`, and a `0x42`-byte formatting extent. It writes `0x203a` little-endian before the digest and signature on the checked direct-buffer paths. The separately observed writer at `0x29abef0` also supplies the same source offsets and digest extent. It invokes each field-name helper only when serializer byte `+0xb` equals 1. Digest formatting and its subsequent string writer are separate calls in that variant.

These are selected static ABI observations. Helper semantics, the enclosing action tag, signature verification, digest production and whether a vote is the authoritative reference for a checkpoint are outside this result. The digest width does not identify its algorithm or show equivalence to an app hash. No node or component gate is requested.

## Reproduce

From the repository root with the pinned artifact present:

```sh
python3 research/work-items/RE-005-node115-abci-digest-vote-json/verify.py
objdump -d -M intel --insn-width=16 --start-address=0x29abdc0 --stop-address=0x29abeea artifacts/node/115/hl-node
llvm-objdump -d --x86-asm-syntax=intel --start-address=0x29abdc0 --stop-address=0x29abeea artifacts/node/115/hl-node
```

The TSV preserves 84 selected linked VAs, raw instruction bytes and decoded instructions. GNU objdump 2.45 and LLVM objdump 23.1.4 agree on all 84 byte spans. The verifier checks the ELF digest, reconciles selected unwind extents against the header, resolves the named RIP-relative literals, and rejects one mutated instruction byte for each row. It does not execute the captured code.
