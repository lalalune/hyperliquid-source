# RE-012 snapshot output error ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. All addresses are original ELF virtual addresses.

The snapshot mode-1 output worker calls 0x26a6af0 at 0x26a648c and 0x26a6bc0 at 0x26a64d0. The wrappers both call 0x26e2a40 with a descriptor containing callback 0x24a7c50. The helper result is preserved across the observed normal cleanup paths. The two wrappers use different input layouts and release rules.

- At 0x26a6af0, input RSI is saved as an outer record pointer. Tag 1 calls 0x26ae520 on the pointer at +8. Tag 0 calls the function bound through slot 0x64df4a0 only if +16 is nonzero, passing that word as size and +8 as the pointer. Other tags skip inner cleanup. All normal paths then release the outer record through the same slot with size 40. An unwind path also releases the outer record before resuming.
- At 0x26a6bc0, a nonnegative first word maps to 4. A negative first word maps to that word XOR 0x8000000000000000. Mapped tags 1 through 3 return without local release. Mapped tag 0 calls 0x26ae520 on +16. Remaining tags use the first word as size and +8 as pointer, skipping the call when size is zero. This wrapper does not perform the separate 40-byte outer release. Its unwind path delegates cleanup to 0x26ae890 before resuming.
- The shared slot 0x64df4a0 resolves by RELATIVE relocation to 0x635de30. The callback and the complete downstream release implementations remain outside this packet.

The complete two unwind ranges total 380 bytes and 101 instructions. GNU, LLVM and Capstone agree on the byte partitions. GNU readelf confirms the extents. The verifier checks five instruction windows, two relocation mutations and two identity controls. The captured binary was examined statically. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

Run from the repository root with authenticated inputs, tool versions from tools.json and fresh output paths.

```sh
python3 -B research/work-items/RE-012-snapshot-error-ownership-115/collect.py --out work/snapshot-errors-fresh
python3 -B research/work-items/RE-012-snapshot-error-ownership-115/verify.py --out work/snapshot-errors-check-fresh.json
```
