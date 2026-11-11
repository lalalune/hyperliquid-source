# RE-001: map node115 listener key table set and map record differences

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener limiter calls two table helpers for the same 20-byte key shape. Both compare sixteen bytes and a final dword after the control-byte candidate filter. One uses 32-byte records and stores an additional qword. On a match it returns the previous qword while replacing that word. The other uses 20-byte records and returns the existing-key tag without replacing a payload.

On insertion both publish the selected control byte and its mirrored slot before storing the key. The map writes its value qword in the same insertion route. The retained comparison and record addresses distinguish these containers without interpreting the key or policy of the caller.

The retained 2 full FDEs cover 843 bytes and 229 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-key-table-layouts-115/collect.py --out work/consensus-key-table-layouts-fresh
python3 -B research/work-items/RE-001-consensus-key-table-layouts-115/verify.py --out work/consensus-key-table-layouts-check-fresh.json
```
