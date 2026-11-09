# Variable-width value encoder

Component evm; subordinate evidence under evm-family3-typed-envelope-115.
Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x4fb2b40..0x4fb2d06`: 454 bytes, 108 instructions.

## Recovered bounded contract

At 0x4fb2b56 buffer+0x1a selects formatting versus binary conversion.
Nonzero mode builds a descriptor referring to the original value pointer;
AL=0 after the indirect formatting call sends the scratch span to 0x57cf5d0.
RAX=2 becomes success 0x8000000000000004; other results preserve RAX/RDX
under high-bit discriminator. AL!=0 enters the recorded panic boundary.

Mode zero calls 0x4fb1a20 with original RSI and stack output. It reads the
returned data pointer at scratch+8 and length at scratch+0x10, sends only
the low 32 bits of that length (R12D) to 0x57cf350, and requires the
header helper's result discriminator 2. Only then does it check remaining
room against the full 64-bit R12 length, conditionally call memcpy for
nonzero length, advance buffer length and write success. This distinction
between header length narrowing and copy length is observed, not treated
as reachable invalid source data. The converter's representation/minimality
and helper header encoding remain unresolved. Temporary storage is released
on normal/error paths when its saved capacity is nonzero; unwind retained.


## Reproduce and limits

```sh
python3 research/work-items/evm-family3-typed-envelope-115/encoders/value/verify.py
```

Python with Capstone 5.0.6 and pyelftools 0.32. Verifies complete target
digest, FDE/CIE ownership, full linear decode and every instruction pin.
RIP operands, indirect call relocation/slot bytes and complete branch
destinations are retained in records.json. 7 operative mutations
must reject with the image-SHA guard disabled. Scalar models are same-author
arithmetic witnesses, not target execution or instruction emulation; their
scope is explicitly narrower than a native differential test.

Assumes valid stable nonaliasing storage, appropriate alignment, descriptor
invariants, adequate backing allocations and normal helper returns. Full
native GNU/Rust/Ghidra/source reproduction, allocator failure and unwind
semantics remain unqualified. No progress gate/component acceptance change.
MANIFEST.sha256 covers all six packet files. Next work is at the explicitly
unresolved helper boundary, not inferred from a caller's name.
