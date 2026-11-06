# RE-012: map node #115 waiter TLS initialization and transfer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: establish how the waiter resolver initializes its TLS node. Earlier lock work identifies the callee as a TLS check; this packet qualifies its state and transfer rules.

Entry state +0x28 equal to one returns the current pointer. A nonzero value other than one returns null. For zero state, a supplied object is consumed by loading and clearing its first qword. If the loaded qword was one, 40 bytes from the supplied object+8 are copied into the TLS node, +0x28 is set to one, and the registration path passes the node and callback 0x5bb5200 through slot 0x64e0510. With no object or a different consumed tag, the fallback constructs a temporary through slot 0x64ec170, then re-reads the TLS state before overwriting the 40-byte payload and setting state one. A reread of one decrements the qword addressed through 0x64ec168 and returns; zero proceeds to registration; other values select the diagnostic path. Callback internals and thread shutdown behavior remain outside scope.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-tls-node-115/collect.py --out work/node115-snapshot-lock-tls-node-fresh
python3 -B research/work-items/RE-012-snapshot-lock-tls-node-115/verify.py --out work/node115-snapshot-lock-tls-node-check-fresh.json
```
