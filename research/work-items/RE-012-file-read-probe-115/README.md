# RE-012 node115 small file read probe

Target Linux x86-64 node #115 SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390. The std census
identifies 0x5c7fa30 as the file specialization of small_probe_read.
This packet closes the probe's argument, retry and append contract
and binds both observed calls from 0x5c75850.

The function zeros a 32-byte stack span and calls imported read
with the file descriptor from the first argument. A -1 return gets
the errno pointer. Errno 4 reuses the same stack span and request
length, after disposing of the packed error. Any other errno returns
RAX=1 and RDX=(u64(u32(errno)) << 32) | 2, without appending bytes.
The retry loop reloads errno after each failed attempt.

A non--1 count above 32 goes to the diagnostic call at 0x5c7fb39.
Otherwise the function compares the count to capacity minus length.
When the count exceeds the available space, the growth helper
receives the vector, old length and additional count, with alignment
and element size both 1. The continuation reloads the pointer and
length before copying the count of bytes to the end of the vector.
Zero skips the copy. The success path publishes the new length and
returns RAX=0 and the appended count in RDX.

At 0x5c758e9 the caller's selected initial path probes when the
available space is below 32. On a zero result it returns success with
count zero. A positive result reloads the vector and continues.
At 0x5c75935 the caller probes when the current length equals the
initial capacity and both tracked capacities agree. Here zero returns
the difference between final and initial lengths, preserving already
completed progress. Either call forwards a probe error. The remaining
read loop, allocator implementation and kernel behavior are context.

## Reproduction

From the repository root with authenticated artifacts and Capstone
5.0.7, GNU 2.45 and LLVM 23.1.4, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-file-read-probe-115/collect.py --out work/file-probe-fresh
python3 -B research/work-items/RE-012-file-read-probe-115/verify.py --out work/file-probe-check-fresh.json
```

Two full FDEs cover 1,047 bytes and 281 instructions. Native exports
agree with Capstone and GNU readelf confirms the FDE extents. The
verifier exercises 11 instruction windows, three dynamic import
writers and two identity controls. The collector scaffold is
adapted from the MIT Build ID packet. Only file bytes are inspected.
