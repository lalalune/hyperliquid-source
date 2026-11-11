# RE-012: recover node #115 poller list detach and source transfer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The collection helper called before poller source cleanup has a one-shot flag at input +0x28. If already set, it returns the empty triple (0,8,0). Otherwise it sets the flag and clears the existing array's logical length at +0x10 before decrementing the saved array references. Each zero transition calls the release slot with the address of the corresponding eight-byte array entry.

The second phase detaches nodes from the list at +0x20. It publishes each successor as the new head, clears the successor's back-link if present, and clears the tail at +0x18 when the head becomes null. It zeros both links in the removed node and converts the interior pointer to its allocation base by subtracting 0x80. The removed allocation is appended to the result sequence. This maps the detach and transfer step, before the caller marks or notifies the collected sources.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-poller-list-detach-115/collect.py --out work/node115-snapshot-poller-list-detach-fresh
python3 -B research/work-items/RE-012-snapshot-poller-list-detach-115/verify.py --out work/node115-snapshot-poller-list-detach-check-fresh.json
```
