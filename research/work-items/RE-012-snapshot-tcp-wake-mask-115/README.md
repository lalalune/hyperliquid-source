# RE-012: map node #115 masked notification callback extraction

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the masked callback extraction in the function called by the notification destructor with mask 0x3f. The fast path claims the byte at object+0x18 with locked CMPXCHG from zero to one. The selected gates test masks 0x05 and 0x0a against the low input byte. The first selected arm copies the 16-byte pair at +0x30, clears the first qword in the object and only queues the pair if that qword was nonzero. The stack list checks index <=31, stores the pair at rsp+0x10 plus index times 16 and increments the count. The second selected arm starts the equivalent load and clear at object+0x40. These observations isolate transfer and mask behavior on successful fast acquisition; they do not establish callback types or full slow-path semantics.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-wake-mask-115/collect.py --out work/node115-snapshot-tcp-wake-mask-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-wake-mask-115/verify.py --out work/node115-snapshot-tcp-wake-mask-check-fresh.json
```
