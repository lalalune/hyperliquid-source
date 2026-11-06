# RE-012: map node115 getcwd growth and owned path result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This packet resolves the owned current-directory result constructed
at 0x5c9a0a0. The selected caller at 0x5ca58f7 uses the RELATIVE
slot 0x64ec908 and checks the leading error marker before loading
the returned pointer and length.

The constructor requests 512 bytes and passes pointer/capacity to
the imported getcwd. A null return reads errno. Only integer 34
reaches the growth call, with current capacity and one additional
byte. The continuation reloads both pointer and capacity before
retrying. Later null returns use the retained errno pointer and
the same comparison. Other errors publish 0x8000000000000000 at
+0 and (u64(u32(errno)) << 32) | 2 at +8, then release the live
allocation when its capacity is nonzero.

On non-null return the code measures the owned buffer with strlen,
so the terminator is excluded from the returned length. A nonzero
length smaller than capacity takes the shrink call. Length zero
takes release and uses pointer sentinel one. The final +0/+8/+16
stores are capacity, pointer and length. The exceptional continuation
releases a live allocation before resuming unwind. Bound allocator
slots and observed calls are retained, without assuming allocator
internals or interpreting the full unwinder. No filesystem operation
or captured code runs during qualification.

The retained 2 full FDEs cover 894 bytes and 229 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 11 instruction/data windows, 5 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-getcwd-owned-result-115/collect.py --out work/getcwd-owned-result-fresh
python3 -B research/work-items/RE-012-getcwd-owned-result-115/verify.py --out work/getcwd-owned-result-check-fresh.json
```
