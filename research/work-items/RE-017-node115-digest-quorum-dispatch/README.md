# RE-017 · Node #115 digest-quorum dispatch and state handoff

- Component ID: `abci` / replay comparison boundary.
- Target release: node #115, Linux x86-64, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: static observations; ELF relocation interpretation and selected-path data-flow are labeled inferences.
- Scope: resolve the call slot left open by [the compact replay row bridge](../RE-017-node115-digest-quorum-row-bridge/README.md), and trace the selected callee's inputs/outputs through the caller's descriptor stores. No runtime state, quorum semantics, or root provenance is claimed.

## Findings

The caller at `0x4e3a020` passes a 0x30-byte temporary output at `RSP+0x60`, the descriptor at `R14`, and a stack input record at `RSP+0x10` to slot `0x64e0f80`. It constructs that input record from the first qword and 32-bit field of its `RSI` input. The `.rela.dyn` entry at the slot has `r_info = 8` and addend `0x1546570`. Under the ELF x86-64 ABI, type 8 is `R_X86_64_RELATIVE`; interpreting that relocation as the loader's slot value yields the target `0x1546570`. This is a static relocation observation, not a runtime read of the slot. The four recorded FDE extents are unwind ranges, not validated function boundaries.

At `0x1546570`, the selected callee retains the output pointer, descriptor pointer, and input-temporary pointer. It reads a 32-bit value at input-record offset `+0`, then checks descriptor byte `+0xa8`. When that byte equals one, it calls the still-unresolved slot `0x64e0f58` with the input-record pointer, compares the returned low byte with descriptor byte `+0xa9`, and, on equality, compares the 32-bit input-record value with the 32-bit value at descriptor `+0x98`. When the first guard is not one, it compares that input-record value with descriptor `+0x98` directly. A matching value on either selected branch writes `0x8000000000000000` to output offset `+8` and returns the output pointer. The incoming replay-row pointer is not passed to this callee; the caller forwards it later to `0x50e6fe0`.

The non-matching paths build a stack record from the descriptor's 16 bytes at `+8`, the row key, and (on the guarded path) the unresolved callback's returned byte. They pass references to that record and other values through slot `0x64df6e8`, then copy the helper-produced bytes into the output object. The selected instructions do not identify the callback's implementation or the meaning of those bytes.

Back in `0x4e3a020`, the caller copies the returned object into descriptor storage beginning at `+0x48`. On the non-sentinel branch it also writes the input-record value to descriptor `+0x98` and copies two returned bytes to `+0xa8` and `+0xa9`. It then forwards the descriptor-associated record and incoming row record to `0x50e6fe0`, which forwards the row-record pointer to `0x537d7b0`. These instructions establish a bounded state handoff along the selected path; they do not establish the state fields' application meaning, persistence, or effect on a canonical root.

## Reproduction

The instructions were decoded from the pinned artifact with Apple LLVM `llvm-objdump` 21.0.0. From repository root, run:

```sh
python3 research/work-items/RE-017-node115-digest-quorum-dispatch/verify.py
```

The verifier checks the target SHA-256, all recorded instruction bytes against file-backed `.text`, each address against the recorded unwind FDE, and the `.rela.dyn` entry for slot `0x64e0f80`. It reports four complete recorded FDE extents and their instruction count. No captured binary was executed. No component gate is requested.

## Limits and next question

Unknowns include the actual runtime binding after relocation, callback implementations at `0x64e0f58` and `0x64df6e8`, their aliasing and side effects, whether the selected branches occur in a real replay, and whether this state reaches any persisted or root-validation path. Next question: resolve those callback targets and their complete data dependencies while retaining the distinction between the descriptor state and the separate `+0x400` history lookup.

Made via @slopdotcash
AI provider/model: OpenAI / GPT-6
Client / agent tooling: Codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"GPT-6","client":"Codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
