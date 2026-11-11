# RE-012: map node #115 snapshot dbOrder field prefix

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The dbOrder arm calls 0x25dd560 from 0x23f6f6a. This worker emits the ordered keys coin, side, limitPx and sz through 0x26077c0 on the selected prefix. The first value goes through the quoted escape worker 0x25bf330, the second calls 0x26a6c80, and both limitPx and sz call 0x24a5b60 at separate sites. Each key has an independent descriptor-status check. The full body is retained; later keys and the numeric value representations are outside the interpreted prefix.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-db-order-fields-115/collect.py --out work/node115-snapshot-db-order-fields-fresh
python3 -B research/work-items/RE-012-snapshot-db-order-fields-115/verify.py --out work/node115-snapshot-db-order-fields-check-fresh.json
```
