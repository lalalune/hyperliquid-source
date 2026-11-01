# node94 length-prefix memory projection

Independently authored, dependency-free `no_std` Rust for the complete
106-byte leaf at ELF VA `[0x55716a0, 0x557170a)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This implements a bounded part of RE-004, not a node or component gate.

`encode(&mut [u8], u64, Payload) -> Result<u32, Refusal>` writes a header,
reads one payload byte, stores it, and returns the raw count 2, 3, or 4.
`Payload::Output(index)` preserves the original header-store-before-load
ordering for overlapping memory; `Payload::External(byte)` supplies a stable
byte from disjoint storage. All `u64` lengths are admitted. Invalid slice
capacity/index is refused without mutation; those errors are new safe-API
behavior, not returns recovered from invalid target pointers.

The third path stores four header bytes and then overwrites byte 3 with the
payload. Keeping that fourth store matters when the payload aliases byte 3.
Only the returned prefix is changed; the rest of the supplied slice survives.
No pointer ABI, volatile/concurrent-memory semantics, wire-format meaning,
whole-caller behavior, or target machine-code equivalence is claimed.

The evidence packet contains the full-domain proof, original byte/FDE locks,
frozen arithmetic/memory-map oracle, input-only native driver measurements,
and controls:
[`RE-004-node94-length-prefix-rust`](../../research/work-items/RE-004-node94-length-prefix-rust/README.md).
Reproduce from the repository root with installed rustc 1.94.1, Python and
Capstone 5.0.7:

```sh
python3 -B -O research/work-items/RE-004-node94-length-prefix-rust/validate.py
```

The validator builds this library with standalone `rustc` and then links its
input-only driver. It creates no Cargo workspace or invented dependency lock;
only these newly built programs run.
