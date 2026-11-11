# Sixteen-byte scalar encoder

Component evm; subordinate evidence under evm-family3-typed-envelope-115.
Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x4f000d0..0x4f00305`: 565 bytes, 127 instructions.

## Recovered bounded contract

Entry RDI is output, RSI points to value storage, RDX is the buffer.
The mode byte here is buffer+0x1a, distinct from the callers' key mode +0x1b.
Mode zero allocates 16 bytes and emits c4, length 16, then exactly
16 payload bytes. No leading-zero trimming occurs on this path.
The aligned MOVAPS input load requires suitably aligned RSI storage. The unpack/shuffle/pack sequence reverses all 16 input bytes: low/high eight-byte halves are individually reversed by PSHUFD 4e and PSHUFLW/PSHUFHW 1b, then packed high-half first. This establishes full-width byte reversal, not two separately ordered limbs.
Mode nonzero instead constructs a formatting descriptor and calls the
relocation-qualified formatter; only after AL=0 does it send the returned
scratch span to the recorded string writer. The formatter's exact spelling
is not recovered here. String writer RAX=2 writes success discriminator
0x8000000000000004; another RAX is stored with RDX under discriminator
0x8000000000000000. Mode-zero copy success writes the same success value.
The three growth sites reserve marker, length and payload separately and
reload buffer fields. Allocation/deallocation and unwind calls are exported
as boundaries, not executed. Concrete source Rust integer types and units
are not inferred solely from storage width.


## Reproduce and limits

```sh
python3 research/work-items/evm-family3-typed-envelope-115/encoders/wide/verify.py
```

Python with Capstone 5.0.6 and pyelftools 0.32. Verifies complete target
digest, FDE/CIE ownership, full linear decode and every instruction pin.
RIP operands, indirect call relocation/slot bytes and complete branch
destinations are retained in records.json. 9 operative mutations
must reject with the image-SHA guard disabled. Scalar models are same-author
arithmetic witnesses, not target execution or instruction emulation; their
scope is explicitly narrower than a native differential test.

Assumes valid stable nonaliasing storage, appropriate alignment, descriptor
invariants, adequate backing allocations and normal helper returns. Full
native GNU/Rust/Ghidra/source reproduction, allocator failure and unwind
semantics remain unqualified. No progress gate/component acceptance change.
MANIFEST.sha256 covers all six packet files. Next work is at the explicitly
unresolved helper boundary, not inferred from a caller's name.
