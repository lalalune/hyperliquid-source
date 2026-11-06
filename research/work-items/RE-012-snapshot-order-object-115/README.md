# RE-012: map node #115 snapshot order object fields

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct and second composite branches in the order-record dispatch converge at 0x23f6ec0. This worker opens an object after checking the writer depth against all ones and clearing the writer state byte. The first key is the seven bytes dbOrder at 0x5ed6d6. The key helper is 0x26077c0, and the value call at 0x23f6f6a is 0x25dd560. The second key is the twelve bytes priorityRate at 0x5ed6dd. It is handed to 0x25922d0, which differs from the first key helper. The packet binds the literal bytes and these dispatch sites. It leaves the child codecs and source-level types open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-order-object-115/collect.py --out work/node115-snapshot-order-object-fresh
python3 -B research/work-items/RE-012-snapshot-order-object-115/verify.py --out work/node115-snapshot-order-object-check-fresh.json
```
