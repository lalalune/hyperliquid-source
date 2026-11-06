# RE-012: map node #115 long address fallback ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the ownership of the long-input address fallback at 0x5c78d90. The producer through 0x64df718 writes a stack result. NEG overflow on its first qword selects the INT64_MIN case. That path forwards the returned pointer to 0x5c81c00, then zeros the first byte and conditionally releases the buffer if the saved size is nonzero. The unwind continuation performs the same first-byte clear and size gate before _Unwind_Resume. The other producer result publishes tag one and pointer 0x64c2fb8. Its release gate uses CF from the earlier NEG, preserved through the intervening JNO, LEA and MOVs, so a nonzero first qword takes the release path. This captures cleanup and ownership only, without executing any resolver.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-long-ownership-115/collect.py --out work/node115-snapshot-address-long-ownership-fresh
python3 -B research/work-items/RE-012-snapshot-address-long-ownership-115/verify.py --out work/node115-snapshot-address-long-ownership-check-fresh.json
```
