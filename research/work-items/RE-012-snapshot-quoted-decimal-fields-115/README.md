# RE-012: map node #115 snapshot quoted decimal field wrapper

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The dbOrder prefix uses 0x24a5b60 for both limitPx and sz. The wrapper calls a formatter through 0x64e5bd8, forwards its bytes to the escape worker 0x25bf330, and has a distinct release call through 0x64df4a0. An unwind branch also calls the release slot. The formatter's numerical semantics remain open; the packet maps the wrapper and its temporary ownership boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-quoted-decimal-fields-115/collect.py --out work/node115-snapshot-quoted-decimal-fields-fresh
python3 -B research/work-items/RE-012-snapshot-quoted-decimal-fields-115/verify.py --out work/node115-snapshot-quoted-decimal-fields-check-fresh.json
```
