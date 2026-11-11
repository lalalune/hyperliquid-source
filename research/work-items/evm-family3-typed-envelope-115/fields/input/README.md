# EVM input-field adapter: conversion versus length/copy

Component `evm`, subordinate to the merged typed-envelope evidence.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b69050..0x5b691d7`: 391 bytes / 109 instructions.

Entry RDI=output, RSI=buffer, RDX/RCX=key address/length, R8=source descriptor.
Any nonzero buffer mode +0x1b first writes the key through `0x57cf5d0`.
RAX!=2 returns discriminator 0x8000000000000000 plus RAX/RDX; mode zero
skips this key call. This closes the adapter left opaque in the payloads.

Buffer byte +0x1a selects a distinct representation route:

- Nonzero: source +8/+0x10 become RSI/RDX to `0x58603e0`, with a stack
  result address in RDI. The produced pointer/length from stack +8/+0x10
  goes to `0x57cf5d0`. Its RAX=2 becomes output 0x8000000000000004;
  another RAX is repackaged with RDX under 0x8000000000000000. On either
  normal return, nonzero temporary capacity at stack +0 triggers the release
  slot with temporary pointer, capacity and EDX=0. Calling this a text route
  is an inference from the conversion/string-writer pairing; exact text
  encoding and converter failures are not recovered.
- Zero: load original source +8 pointer and +0x10 full 64-bit length.
  Pass **only the low 32 length bits** in EDX to `0x57cf350`, with output
  stack slot and buffer. Non-2 stack result is repackaged under the high-bit
  discriminator. On 2, compare full length with capacity-length; unsigned
  greater-than enters growth `0x5963a10`. Nonzero full length calls the
  relocated copy routine with destination storage+current length, original
  pointer and full length. Then add full length to buffer length and write
  0x8000000000000004. Zero length skips the copy.

The length-marker argument and copied byte count therefore have different
widths. Inputs above 2^32 are arithmetic witnesses only, not accepted wire
lengths or valid allocations. Source ownership, numeric meaning of mode bytes,
conversion details and the length-marker encoding remain outside scope.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/fields/input/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decode,
instruction pins, branches and GOT relocations are checked. Eight operative
mutations reject below the image SHA guard. Independent checks cover 65,536
mode/representation pairs plus six length-width boundaries. Body/FDE/CIE,
calls, branches and LSDA address are retained; no target execution/interpreter.

Cleanup-pad bytes are retained but LSDA selection is not decoded: no unwind
closure claim. Valid stable nonaliasing pointers, capacity invariants and normal
helper returns are assumptions. Full native-tool suite/reproduction remains
unqualified. No gates change. Next: recover the converter and marker writer
before inferring exact text/binary encodings.
