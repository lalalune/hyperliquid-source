# RE-012: map node #115 TCP packed reference release gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: identify the packed-count gate in the auxiliary release routine called by the nonzero-tag TCP destructor.

A null first qword skips the packed decrement. Otherwise the helper performs locked XADD(-64) at the pointed-to address, then shifts the pre-update word right by six. An extracted value of one calls through the pointer at object+0x10, slot+0x10. An extracted value of zero calls the diagnostic helper and reaches UD2. A value above one skips both calls. Subtracting 64 preserves the low six bits modulo 64-bit arithmetic. The ordinary continuation calls 0x5ce1e50 on wrapper+0x18, checks that reference after a decrement, and separately checks an optional reference at +8. The final tail release passes the wrapper base and size 0x78. These are local state and ownership observations without an assertion about the dynamic table's type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-packed-ref-115/collect.py --out work/node115-snapshot-tcp-packed-ref-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-packed-ref-115/verify.py --out work/node115-snapshot-tcp-packed-ref-check-fresh.json
```
