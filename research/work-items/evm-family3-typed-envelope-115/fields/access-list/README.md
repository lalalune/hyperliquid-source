# EVM access-list adapter: field key versus collection type label

Component `evm`, subordinate to the merged typed-envelope evidence.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b691e0..0x5b692ac`: 204 bytes / 55 instructions.

Payload callers supply RDI=output, RSI=buffer and RDX=collection storage.
The earlier payload evidence retained only the bounded key-writing prefix;
this packet closes the complete adapter's argument and tail-call contract.

Mode byte buffer+0x1b must equal exactly 1 to emit the field key. The inline
stores write aa followed by lowercase `accessList`: imm64
0x694c737365636361, then imm16 0x7473. Capacity==length and remaining room<=9
enter separate `0x5963a10` growth calls with required lengths 1 and 10,
alignment arguments 1, then reload fields and rejoin the corresponding stores.

In every mode, continuation loads RDX=0x93e359 and ECX=10. The pinned pool
bytes spell uppercase `AccessList` for those ten bytes; it is distinct from the
lowercase field key. R8 becomes the original collection pointer. Output RDI
and buffer RSI remain the adapter convention, then `0x5b69243` tail-jumps
to actual FDE start `0x52f51a0`. The latter receives the collection type-name
arguments; whether and how it emits them is not claimed. There is no local
result repackaging or collection-element loop in this adapter.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/fields/access-list/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full digest/FDE, complete decode,
instruction/data pins, branches and actual external tail start are checked.
Eight operative mutations reject below image SHA guard; all 256 mode bytes
are checked in an independent prefix model. Full bytes/FDE/CIE/calls/branches
and pool context retained. No captured instruction execution/interpretation.

Valid stable nonaliasing storage, buffer invariants and normal growth returns
are assumptions. Nested collection encoding, allocation failure, runtime type
names and full native-tool suite remain unqualified. No gates change.
Next: recover the collection serializer and each access-list entry independently.
