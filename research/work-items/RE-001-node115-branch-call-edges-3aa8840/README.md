# RE-001: branch-conditioned direct calls at node #115 FDE `0x3aa8840`

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Scope: one 63-byte unwind-described range and its two direct calls, branch conditions, callee FDE entries, and one RIP-relative `.data.rel.ro` address passed on the second call.
- Exclusions: no function/source name, high-level type, helper behavior beyond existing independent evidence, whole call graph, or component-gate claim.

## Question

Which byte conditions in the FDE starting at `0x3aa8840` select its two direct calls, and do those calls land on exact FDE starts in node #115? This is a narrow call-context follow-up to the surrounding RE-001 FDE inventory. The existing [selected call-edge map, PR #5074](https://github.com/lalalune/hyperliquid-source/pull/5074) covers a different caller at `0x3a7d0d0`; this packet records the previously unlisted sites `0x3aa885d` and `0x3aa8875`.

## Observations from pinned bytes

The source range is `[0x3aa8840, 0x3aa887f)`, with body SHA-256 recorded in `edges.json`. It reads one byte from the initial RDI address.

- Byte `0x16` takes a short branch to `xor eax,eax; ret`, reaching neither direct call.
- Byte `0x12` branches directly to the call at `0x3aa885d`.
- Byte `0x15` reads a qword at the initial RDI address plus `0x18`: zero reaches `0x3aa885d`; nonzero reaches `0x3aa8875`.
- Other byte values apart from `0x16` and `0x12` reach `0x3aa8875`.
- The first direct relative call resolves to `0x3b62630`, an exact FDE entry with range `[0x3b62630, 0x3b627ed)`.
- The second resolves to `0x3b676e0`, an exact FDE entry with range `[0x3b676e0, 0x3b67744)`.
- Before the second call, the code places `RSP+7` in RSI and computes `0x646fb38` into RDX. That address is file-backed `.data.rel.ro`; the packet stores its first 32 bytes and hash without assigning a source-level meaning.

`window.txt` preserves the bounded objdump listing. The verifier independently checks the target SHA-256, source and callee FDE records, source body hash, instruction coverage, conditional-branch destinations, both `call rel32` destinations, and the RIP-relative data address. It uses the repository's ELF and FDE parsers. No captured target was executed or copied.

## Reproduction

```sh
python3 -B research/work-items/RE-001-node115-branch-call-edges-3aa8840/verify.py
python3 tests/test_node115_branch_call_edges_3aa8840.py
make verify
make catalogue-check
```

The saved listing was captured with Apple LLVM objdump 21.0.0 and remains historical evidence. The default checker accepts GNU and LLVM formatting while checking the retained listing's addresses and bytes against the authenticated source, and independently derives every semantic record with the current decoder. `--exact-capture` additionally requires the recorded decoder and exact listing text. To retain a separate current-provider reproduction, use `--write --out work/branch-call-edges-reproduction`; a different provider cannot overwrite the historical capture in place.

## Limits

FDEs are unwind-described extents, not proof of source-level function boundaries. The branch conditions are stated as machine-level byte and memory predicates. The meanings of the qword, the `.data.rel.ro` object, and the two helpers are not inferred here. The packet adds one caller's local edges and does not claim the full callers or callees of any target. All component gates remain unchanged.

Made via @slopdotcash
AI provider/model: OpenAI / GPT-6
Client / agent tooling: Codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"GPT-6","client":"Codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
