# RE-001: map node115 consensus lookup thread-local key matching

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The consensus listener packet identifies the caller of 0x29b4360. This packet resolves the selected thread-local key scan. A zero byte at input +0x20 tail-dispatches to a separate helper. Otherwise the routine reads a thread-local state byte, handles its one and two states separately, and uses a bound initialization path before writing state one for the remaining selected states.

The scan uses 56-byte records and compares the qword at +0x18, dword at +0x10 and span length at +0x08. Only after those equalities does it compare the referenced key bytes using bcmp and that length. Failed comparisons advance by one full record. This records the local cache-key match independently of how the final lookup result is derived.

The retained 1 full FDEs cover 2361 bytes and 453 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-peer-lookup-cache-key-115/collect.py --out work/consensus-peer-lookup-cache-key-fresh
python3 -B research/work-items/RE-001-consensus-peer-lookup-cache-key-115/verify.py --out work/consensus-peer-lookup-cache-key-check-fresh.json
```
