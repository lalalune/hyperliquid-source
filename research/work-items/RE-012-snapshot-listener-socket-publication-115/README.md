# RE-012: recover node #115 listener socket setup and publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The listener factory selects family 10 when the leading input word equals one and family two otherwise. Both arms call socket with type 0x80001 and protocol zero, then call setsockopt with level one, option two and a four-byte integer set to one. The family-dependent address preparation swaps the port bytes and chooses a bind length of 28 or 16 bytes, respectively.

The shared tail calls bind and then listen with backlog 128. Only after both succeed does it publish the descriptor at output offset four and tag zero at offset zero. Socket failure publishes tag one and the packed errno without closing a descriptor. Failure after successful socket creation captures errno before calling close on the acquired descriptor. The relocation names for the five imports are socket, setsockopt, bind, listen and close.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-listener-socket-publication-115/collect.py --out work/node115-snapshot-listener-socket-publication-fresh
python3 -B research/work-items/RE-012-snapshot-listener-socket-publication-115/verify.py --out work/node115-snapshot-listener-socket-publication-check-fresh.json
```
