# RE-007: #115 registration value row handoff

This packet follows the optional registration value construction left open by [the asset-registration caller packet](../RE-007-node115-asset-registration-caller-name-rules/README.md). Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. This is static evidence; target instructions are not executed or emulated.

## Selected call and input

In the prior caller `0x38b3f90`, after the selected successful entry result, the second result qword is saved at `rsp+0xa8`. When the byte at `rsp+0x1c` is nonzero, the caller creates a three-qword descriptor at `rsp+0xf0`: a pointer to that saved qword followed by two zero qwords. It calls `0x3bcb6c0` with that descriptor and a result buffer at `rsp+0xb0`, then passes the result and a separately prepared key to the function reached through slot `0x64e6bc8`, whose relative relocation addend is `0x42096d0`. This is a conditional static call chain, not proof of a live registration or of the map operation's semantics.

`0x3bcb6c0` copies the descriptor to its own stack and calls `0x3db4e40`. [The existing row-window packet](../RE-001-node115-oracle-kind-row-window/README.md) describes the latter's valid, nonoverflow result: a bounded vector of 0x38-byte records based on the descriptor's index and offset, with at most three rows and the shared object's first qword appearing at each row's `+8`. Given the selected caller's zero index and offset and the former packet's stated valid-input and normal-return conditions, this produces rows for indices 0, 1 and 2. This packet authenticates the producer body and its call and input bindings; it does not re-prove the existing packet's complete loop or allocator contract.

## Post-construction handling

The wrapper checks the returned length. Lengths below 2 skip its first helper; lengths 2 through 20 call `0x436d300` with the row pointer and length, while lengths of 21 or more call the function reached via slot `0x64e9278`. These helper bodies and their ordering effects are outside this packet. The wrapper then calls `0x3d9b0c0` with the vector header.

The latter reads the row count at header `+0x10` and row base at `+8`, and returns directly for fewer than two rows. It compares adjacent 0x38-byte records: byte 0 must match; if that byte is nonzero, the qword at `+8` must also match; byte 1 must then match. Its later loop copies or swaps full 0x38-byte records and stores a revised count at header `+0x10`. These conditions and stores establish a selected in-place compaction mechanism, not the source-level record identity, equality contract for every possible invalid memory state, or the behavior of the preceding helpers.

After this call the wrapper reloads the count and compares it to `0x40`. On the `<= 0x40` branch it constructs a header and calls `0x4564770`; on the other branch it multiplies the count by `0x38`, builds a range, calls `0x388bf90`, and writes `0x8000000000000000` in the output's first qword. No result semantics are assigned to these helpers. In particular this packet does not claim that either branch is reachable from the selected caller, because the intermediate helpers' full contracts are not established here.

## Reproduction and limits

`instructions.tsv` records the caller window and complete bodies of the wrapper, compactor and row producer. `verify.py` authenticates the complete target digest and four indexed FDE/body hashes, verifies 376 instruction spans and 51 byte pins, resolves seven targets and the call-slot relocation, and rejects seven corruptions. It decodes bytes but does not execute or emulate them. Independently reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-007-node115-registration-value-rows/verify.py` using Python with Capstone. Allocator failures, helper behavior, output type and ownership, dynamic effects, other caller paths, cross-version equivalence and an end-to-end node are not established. No completion gate is requested.
