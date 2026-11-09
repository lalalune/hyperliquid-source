# Prefixed lowercase hex scalar path

Component evm; subordinate evidence under evm-family3-typed-envelope-115.
Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x58603e0..0x5860563`: 387 bytes, 104 instructions.

## Recovered bounded contract

Entry RDI=output descriptor, RSI=input pointer, RDX=input length.
The computed requested size is (2*length+2) modulo 2^64. Zero and signed
negative results branch to failure boundaries; no general input-length
validity guarantee is inferred. Successful allocation stores the literal
bytes 30 78 (0x), then writes two bytes per input byte, high nibble first.
The pinned 16-byte alphabet at the RIP-relative table is lowercase hex.
The scalar loop processes pairs, followed by an odd final byte. Empty
input still allocates two bytes and returns 0x. Output descriptor offsets
0/8/0x10 receive computed size, allocation pointer and computed size.

A lazily loaded CPU-feature word bit 0x200 selects 0x4ef75a0 with input,
length and destination+2; this helper is a separate boundary, so this
packet qualifies the visible scalar path only. The initializer, allocation,
failure and unwind calls are retained with relocation evidence. No claim
of CPU helper equivalence or captured execution is made.


## Reproduce and limits

```sh
python3 research/work-items/evm-family3-typed-envelope-115/encoders/hex/verify.py
```

Python with Capstone 5.0.6 and pyelftools 0.32. Verifies complete target
digest, FDE/CIE ownership, full linear decode and every instruction pin.
RIP operands, indirect call relocation/slot bytes and complete branch
destinations are retained in records.json. 8 operative mutations
must reject with the image-SHA guard disabled. Scalar models are same-author
arithmetic witnesses, not target execution or instruction emulation; their
scope is explicitly narrower than a native differential test.

Assumes valid stable nonaliasing storage, appropriate alignment, descriptor
invariants, adequate backing allocations and normal helper returns. Full
native GNU/Rust/Ghidra/source reproduction, allocator failure and unwind
semantics remain unqualified. No progress gate/component acceptance change.
MANIFEST.sha256 covers all six packet files. Next work is at the explicitly
unresolved helper boundary, not inferred from a caller's name.
