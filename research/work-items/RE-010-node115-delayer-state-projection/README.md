# RE-010: #115 action-delayer state projection

This packet connects three previously separate observations: the `action_delayer` decoder's selected output transfer, the materializer's suffix projection and the engine's selected queue-extractor argument. It answers a bounded part of the next question in [the start-fee-trial packet](../RE-010-start-fee-trial-115/README.md), not the complete ownership question. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses are virtual addresses. No target instruction is executed or emulated.

## Byte-range join

The earlier RE-010 packet identifies the selected `ActionDelayer` decoder result at stack `+0x848` and observes its `0x78`-byte copy into a state result at `+0x25a0`. This packet rechecks all eight source and destination instruction pairs at `0x185d881..0x185d8f9`: seven 16-byte transfers and a final 8-byte transfer.

The independent [materializer packet](../RE-016-state-materialize-3c2e860-115/README.md) established a `0x27a8`-byte input and `0x42c8`-byte output, with the suffix shifted by `0x1b20`. Here `0x3c2e860` saves its incoming source and destination pointers in `r14` and `rbx`, forms `r12 = source + 0x25a0` at `0x3c2ea91`, and, at `0x3c2eebb..0x3c2ef21`, loads the same seven 16-byte ranges and final 8-byte range from `r12`. It stores them to output `+0x40c0..+0x4138`. The verifier checks that the selected code between assignments and copies does not itself write those callee-saved registers; normal callees are assumed to obey the x86-64 ABI.

Consequently, **if** the materializer's input is the selected decoded state, its buffers are valid and non-overlapping, and the stated path and ordinary call returns occur, the previously observed 120-byte region is copied byte-for-byte from decoded-state `+0x25a0..+0x2618` to materialized-state `+0x40c0..+0x4138`. The displacement is `0x25a0 + 0x1b20 = 0x40c0`. This is a conditional join across independently established observations; the packet does not prove that this exact decoder result is passed to that materializer.

## Boundary before extraction

The selected engine site at `0x2d237ad` forms `base + 0x40c0` in its second argument and calls through `0x64e4f00` at `0x2d237d7`; the target's relative relocation addend is the previously studied queue extractor `0x3bed8a0`. It separately supplies the selected base's `+0x60` and `+0x68` fields in a stack argument. The matching offset is a concrete bridge between the materialized layout and this callsite, conditional on the two base pointers naming the same value at the relevant time. This packet does not establish that pointer identity.

A separate loader site at `0x3c1294b..0x3c12959` forms `base + 0x40c0` and calls through `0x64e4f10`; its relative relocation addend is `0x3bec320`. Open PR #4722 independently studies the loader and identifies this as a subobject initializer. Its body and possible writes are not characterized here. Thus even when the initial projection occurred, this intervening call and any other mutation are explicit barriers to claiming that the extractor sees unchanged bytes or the same ownership. This packet does not claim a restored runtime instance, exact object lifetime or a complete state-to-execution path.

## Evidence and reproduction

`instructions.tsv` records the selected copy, pointer and call windows. `verify.py` authenticates the target digest, five indexed FDE bounds and body hashes, decodes each complete FDE, checks 45 selected instruction spans and 41 pins, checks both indirect slots and relative relocations, verifies eight byte-range joins and rejects eight modified anchors. The code also scans the indicated materializer interval for writes to its saved registers. Counts are evidence denominators, not execution or coverage claims. Run `PYTHONPATH=tools python research/work-items/RE-010-node115-delayer-state-projection/verify.py` from the repository root with Capstone installed.

Buffer aliasing, failure and unwind paths, dynamic pointer identity, loader subobject effects, queue contents and cross-version equivalence remain unresolved. No component completion is claimed.
