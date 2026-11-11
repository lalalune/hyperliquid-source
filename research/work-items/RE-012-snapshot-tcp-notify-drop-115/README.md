# RE-012: map node #115 notification object dynamic cleanup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the zero-count target of the descriptor-vector cleanup. Its slot 0x64dfe38 has ELF RELATIVE addend 0x5ce88e0. The callee dereferences its input field and invokes 0x5cfd1d0 with allocation+0x80 and 0x3f. It then reads the optional dispatch tables at +0xb0 and +0xc0 in order. Each nonnull table contributes a call through its +0x18 slot, passing the adjacent +0xb8 or +0xc8 qword respectively. After both normal continuations, an all-ones base bypasses the outer decrement. Otherwise the locked decrement at +8 gates a 0x100-byte release. These are static ordering and operand observations; the dynamic target identities are unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-notify-drop-115/collect.py --out work/node115-snapshot-tcp-notify-drop-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-notify-drop-115/verify.py --out work/node115-snapshot-tcp-notify-drop-check-fresh.json
```
