# RE-012: recover node #115 random fill progress and flag retry

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct random-fill arm checks the imported getrandom entry for availability. In the selected flag-dependent loop it passes the current destination and remaining count, choosing flags one or four from the global byte at 0x64fed95. After a nonnegative result it checks that the count does not exceed the remaining request, advances the pointer and subtracts the returned count before deciding whether to iterate.

Return -1 instead reads errno and dispatches values one through 38 through the table at 0x948738. One selected retry arm clears the global flag, reloads it, recomputes flags and retries without advancing the destination. This packet maps the selected import loop and its progress and retry state. Other provider paths remain outside the recovered behavior.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-random-fill-progress-115/collect.py --out work/node115-snapshot-random-fill-progress-fresh
python3 -B research/work-items/RE-012-snapshot-random-fill-progress-115/verify.py --out work/node115-snapshot-random-fill-progress-check-fresh.json
```
