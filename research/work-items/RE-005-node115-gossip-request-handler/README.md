# RE-005: node 115 selected request-result handler

This packet traces the next helper following the 24-byte request result handoff identified in [PR #5069](https://github.com/lalalune/hyperliquid-source/pull/5069). It is independently anchored to Linux x86-64 node #115 artifact `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The earlier `RE-005-node115-gossip-rpc-request` identifies the decoder; this packet concerns the selected handler at `0x5a5dbc0`, not all consumers or full network semantics.

At call `0x5a61539`, caller `0x5a60a50` passes a pointer to the 24-byte stack copy as `rcx`. The RIP-relative slot `0x64ebfb0` has an ELF relative relocation to `0x5a5dbc0`; this is the recorded relocation target, not a guarantee about runtime binding. On entry let `T`, `A`, and `B` be the three qwords at `rcx+0`, `+8`, and `+16`, and let `D` be `edx`. The selected observations assume valid non-aliasing storage, ABI-preserving calls, and the relocated target actually being used.

## Handler's selected dispatch

- If the full 64-bit T is zero, the code loads A and B and calls `0x4fac7e0` with the saved D. If T is nonzero and its low 32 bits equal 1, it calls `0x4fac310` and writes output qword 0 as 4. Other nonzero T values enter `0x5a5dc4b`, where the selected lock-acquired path copies 48 bytes from an object at offsets `+0x18..+0x47` to output `+0..+0x2f`. The full-width zero test followed by a 32-bit equality test matters for noncanonical T values.
- On T zero, the code enters the range calculation if either `(AL | (D == 0x0100007f)) == 1` after `0x4fac7e0`, or the subsequent fallback recognizes `D & 0xff == 0x0a`, `(D & 0xffff) == 0xa8c0`, or `(D & 0xf0ff) == 0x10ac`. AL is the helper's returned low byte, and `|` is a bytewise OR; this observation does not assume AL is Boolean. Other conditions reach a separate output construction.
- On the range-calculation path the unsigned subtraction `B - A` branches on borrow. A borrow constructs output qword 0 as 3, qword `+8` as 1, and qword `+0x10` as 1. Without borrow, a difference greater than 99 constructs the same first two qwords with `+0x10` equal to 2. Differences 0 through 99 continue to another locked-object path whose result is not resolved here. These are numeric checks on the two raw qwords, not an assertion of message count, field units, or wire framing.

The lock failure path, the complete `0x4fac7e0` and `0x4fac310` helpers, the remaining selected range path, output meanings, pointer identity and live reachability remain open. The observations do not assert that the qwords are semantically valid requests or that a response is sent.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-005-node115-gossip-request-handler/verify.py`. The checker authenticates the ELF and two FDE bodies, verifies selected instructions, control-flow targets, relocation and numeric boundary examples, and rejects byte mutations. It parses and disassembles bytes only; it does not execute or emulate the target.
