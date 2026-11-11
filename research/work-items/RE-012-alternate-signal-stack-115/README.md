# RE-012: map node115 guarded alternate signal stack setup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The stack setup path queries sigaltstack with a null new-stack
pointer and a zero-initialized 24-byte output. It tests bit 1 of
the returned flags. If the bit is clear, the path returns zero,
leaving an existing alternate stack alone.

If the bit is set, the usable size is max(unsigned getauxval(0x33),
0x2000). The mapping length adds the shared page size at 0x6500048.
The mmap64 call uses null address, protection 3, flags 0x20022,
fd -1 and offset zero. A mapping result of -1 enters the errno
diagnostic path. A successful mapping passes its first page to
mprotect with protection zero. Nonzero mprotect return takes a
separate diagnostic route.

On the ordinary path the new stack pointer is mapping base plus
page size, flags zero and size the usable length. The second
sigaltstack call receives that record and a null old-stack pointer.
The return sequence loads the recorded usable pointer without
testing that call's result. This scope follows the alternate stack
path only, with earlier thread-stack discovery as context.

The retained 1 full FDEs cover 682 bytes and 159 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 8 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-alternate-signal-stack-115/collect.py --out work/alternate-signal-stack-fresh
python3 -B research/work-items/RE-012-alternate-signal-stack-115/verify.py --out work/alternate-signal-stack-check-fresh.json
```
