# RE-012: map node115 thread entry name truncation and handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

Thread entry reads a name pointer at record +0x18 and its size
word at +0x20. The named arm zeroes 16 stack bytes, subtracts
one from that size, and copies at most 15 bytes. The size-one
arm leaves all 16 bytes zero. The null-pointer arm requires a
nonzero global id at 0x64fffe8 matching the object word before
selecting a four-byte fallback. Otherwise it skips naming.

The selected 16 bytes are passed to pthread_setname_np using
the handle from pthread_self. The call result is not tested.
The continuation loads the callback fields, decrements the
record reference count and calls the release helper on zero.
It then enters the alternate stack helper before dispatching
through callback table +0x18. The packet scopes name selection
and handoff separately from alternate stack construction.

The retained 1 full FDEs cover 509 bytes and 137 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-thread-name-projection-115/collect.py --out work/thread-name-projection-fresh
python3 -B research/work-items/RE-012-thread-name-projection-115/verify.py --out work/thread-name-projection-check-fresh.json
```
