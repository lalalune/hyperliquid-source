# RE-012: map node #115 TCP four-reference unwind continuation

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the shared four-field cleanup called by both TCP release layouts. The ordinary path visits optional references at offsets +8, +0x18, +0x28 and +0x38 in order. Each nonnull pointer is atomically decremented and the zero-count path passes the corresponding field address through slot 0x64e17c8. The final ordinary callback is a tail jump. Three distinct unwind entries preserve the exception and enter the remaining-field sequence at +0x18, +0x28 or +0x38 respectively. The continuation uses an ordinary call for the last callback before resuming unwinding. This maps the four-field cleanup sequence rather than inferring concrete field types.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-four-ref-unwind-115/collect.py --out work/node115-snapshot-tcp-four-ref-unwind-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-four-ref-unwind-115/verify.py --out work/node115-snapshot-tcp-four-ref-unwind-check-fresh.json
```
