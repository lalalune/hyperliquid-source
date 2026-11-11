# RE-012: map node115 readlink truncation retry and owned result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This packet maps the owned symlink-target result at 0x5c9f5c0
and its direct adapter at 0x5cad78c. The adapter preserves the
result pointer and forwards its third argument as the pathname
argument. The input is the pointer presented to imported readlink.
Upstream pathname preparation is outside the selected scope.

The constructor requests 256 bytes. It calls readlink with the
path pointer, owned buffer and capacity. A return equal to capacity
takes growth with the returned count and one additional byte, then
reloads the buffer and capacity before the next call. The retry
is driven by the full-buffer return, not by errno. Each retry
reuses the original pathname pointer and starts at the new buffer
base. The result is the most recent returned count rather than a
sum of previous attempts.

A non--1 return below capacity takes shrink for a positive count.
Zero frees the allocation and stores pointer sentinel one. The
success layout at +0/+8/+16 is capacity, pointer and count, with
no strlen or terminator scan in this body. An exact -1 reads errno,
stores 0x8000000000000000 and (u64(u32(errno)) << 32) | 2 at +0/+8,
and releases a live allocation. The exceptional continuation also
releases the owned allocation before unwind resume. The contract
stops at imports and bound allocator slots. No kernel behavior,
symlink traversal or captured execution is used to qualify it.

The retained 2 full FDEs cover 467 bytes and 133 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 10 instruction/data windows, 4 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-readlink-owned-result-115/collect.py --out work/readlink-owned-result-fresh
python3 -B research/work-items/RE-012-readlink-owned-result-115/verify.py --out work/readlink-owned-result-check-fresh.json
```
