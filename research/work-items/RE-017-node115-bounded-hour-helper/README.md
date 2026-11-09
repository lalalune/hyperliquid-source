# RE-017 · Node #115 bounded hour-field conversion helper

- Component ID: `abci` / replay comparison boundary.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: byte and relocation observations; arithmetic identity is independently checked over the admitted input range; semantic labels remain limited to the literal evidence.
- Scope: resolve the `0x64e0f58` callback left open by [PR #5559](https://github.com/lalalune/hyperliquid-source/pull/5559), including the input field, successful output, and visible bound. Excludes the separate `0x64df6e8` callback, runtime state, persistence, replay success, and root provenance.

## Findings

The call at `0x154659a` uses slot `0x64e0f58` with `RDI` pointing to the input record. Its `.rela.dyn` entry has symbol index zero, relocation type 8, and addend `0x1567ad0`. Under the ELF x86-64 relocation definition, type 8 is `R_X86_64_RELATIVE`; the static loader-resolved target is therefore `0x1567ad0`. This does not read a relocated pointer from a running process.

The callee's unwind-described range is `0x1567ad0..0x1567b94`. It loads a 32-bit unsigned value `x` from input offset `+4`. Values `x >= 0xe1000` branch to the error path. For values below that bound, it computes `x * 0x91a2b3c5 >> 43`, then values `x >= 0x15f90` also branch to the error path. Since `0x15f90` is 90,000, its normal return range is `0 <= x < 90,000`.

For every integer in that admitted range, the multiply-shift equals `floor(x / 3600)`. The packet verifier checks this identity for all 90,000 accepted inputs and confirms the returned value is at most 24. At the call site, the returned low byte is compared with descriptor byte `+0xa9`. A nearby length-prefixed literal at `0x436682` is `hour out of range: `; the quotient's relationship to hours is an inference supported by that literal and the arithmetic, not a recovered source-level type or full time-field contract.

The range failures enter code that passes the same literal through a helper and calls a reporting slot. That slot's implementation and all runtime effects are outside this packet. FDE extents are unwind ranges, not validated function boundaries.

## Reproduce

The instruction bytes were decoded from the pinned artifact using Apple LLVM `llvm-objdump` 21.0.0 on macOS arm64 (Python 3.14.3 for the verifier). From repository root, the recorded ranges can be disassembled with:

```sh
xcrun llvm-objdump --disassemble --start-address=0x1546570 --stop-address=0x15466f3 artifacts/node/115/hl-node
xcrun llvm-objdump --disassemble --start-address=0x1567ad0 --stop-address=0x1567b94 artifacts/node/115/hl-node
```

Then run the packet verifier:

```sh
python3 research/work-items/RE-017-node115-bounded-hour-helper/verify.py
```

The verifier checks the artifact digest, every instruction byte in the two recorded FDE extents, FDE index membership, the relocation tuple, the bounded literal bytes, and the multiply-shift identity for `0..89999`. It does not execute the captured binary. No component gate is requested.

No implementation or comparison build is claimed. The byte-span checks and the `89,999`/`90,000` boundary assertions are the positive and negative controls for this bounded arithmetic claim; they do not validate a full record parser or runtime behavior.

## Limits and next question

The record's producer and complete layout are not identified here; only the `+4` read is established. The result's comparison with descriptor `+0xa9` does not establish that the byte is a canonical digest or a root input. The `0x64df6e8` callback, error reporter, runtime branch frequency, persistence and root-validation effects remain unresolved. Next question: determine whether the checked `+4` value comes from a validated time field and trace the other callback without conflating descriptor state with the independent `+0x400` history lookup.

Made via @slopdotcash
AI provider/model: OpenAI / GPT-6
Client / agent tooling: Codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"GPT-6","client":"Codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
