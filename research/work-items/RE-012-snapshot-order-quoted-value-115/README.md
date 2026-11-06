# RE-012: map node #115 snapshot quoted order value

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The composite order-record dispatch invokes 0x2630fd0 with immediate arguments 42 and 20. The wrapper first calls indirectly through 0x64e4d08. It appends an opening double quote, delegates bytes to the escaping worker at 0x25bf330, then appends the closing quote. A separate route calls the same escaping worker with a length of two. Each recorded full-capacity arm invokes 0x231e050 before rejoining its quote write. This packet binds the framing around the escape call and leaves interpretation of the incoming bytes and helper result open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-order-quoted-value-115/collect.py --out work/node115-snapshot-order-quoted-value-fresh
python3 -B research/work-items/RE-012-snapshot-order-quoted-value-115/verify.py --out work/node115-snapshot-order-quoted-value-check-fresh.json
```
