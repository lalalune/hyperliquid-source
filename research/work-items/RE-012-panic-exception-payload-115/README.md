# RE-012: map node115 panic exception payload creation and take

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The raising wrapper calls the incoming vtable slot +0x20,
allocates 56 bytes and writes the class word and cleanup
pointer. It clears the two words at +0x10 and writes the
local marker and payload pair at +0x20/+0x28/+0x30. It
tail-calls _Unwind_RaiseException with the allocation.

The take wrapper checks class and the local marker. When
both match, it extracts the pair and releases the 56-byte
allocation. A different class calls _Unwind_DeleteException.
The matching class with a different marker takes a distinct
helper. This packet covers payload ownership at the unwind
boundary without raising an exception.

The retained 2 full FDEs cover 229 bytes and 64 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-panic-exception-payload-115/collect.py --out work/panic-exception-payload-fresh
python3 -B research/work-items/RE-012-panic-exception-payload-115/verify.py --out work/panic-exception-payload-check-fresh.json
```
