# EVM destination field: key, address tail and nil

Subordinate evidence for the merged family-3 envelope, component `evm`.
Target node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b6ac70..0x5b6ad83`: 275 bytes / 75 instructions.

Entry RDI=output, RSI=buffer, RDX=destination object D. This resolves the
destination call left opaque in the Eip1559 payload; it does not recover the
address encoder. The buffer mode byte is +0x1b, capacity/storage/length +0/+8/+0x10.

- Any nonzero mode emits fixstr `a2 74 6f` (`to`), not just mode 1.
  Full-buffer and insufficient-room paths call `0x5963a10`, reload fields,
  and rejoin the marker/name stores.
- At `0x5b6acb4`, byte [D] is compared to exactly 1. That value increments
  D by one and tail-jumps to `0x4e2e020` with RSI=D+1, RDX=buffer and the
  original output RDI. The verifier pins the tail to an actual FDE start.
- Every other byte takes the nil path: reserve one byte if needed, store
  c0, increment length, write output qword 0x8000000000000004 and return.
  Other output words are untouched. Invalid tags are branch witnesses only.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/fields/destination/verify.py
```

Python / Capstone 5.0.6 / pyelftools 0.32. Full target digest, actual FDE,
complete decoding, all instruction pins, branch boundaries and external tail
are checked; `--write` regenerates body/FDE/CIE/call/branch exports. Eight
operative mutations reject below the image SHA guard. Independent conditional
models cover 65,536 mode/tag pairs, not captured-instruction execution.

Assumptions: valid stable nonaliasing pointers, capacity invariants and normally
returning growth helper. Address bytes, allocator failures, valid Rust enum
representations and whole EVM behavior remain open. Full native-tool suite is
unqualified on this host; no component gate changes. Next: close the numeric
value and byte-input field adapters separately from this destination policy.
