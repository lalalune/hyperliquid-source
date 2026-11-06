# RE-012: map node #115 TCP packed index compare and swap

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the packed index update called on the TCP release wrapper's +0x18 field. This is a separate callee from the packed reference decrement.

On the selected path the qword at state+0x18 supplies two 32-bit halves. If its low half equals state+0x20, the routine returns without an update. Otherwise it computes next=low+1 modulo 2^32. If high equals low it proposes both halves equal to next. If high differs from low and next equals high it takes a separate diagnostic branch. Otherwise it preserves high and replaces low. A locked CMPXCHG commits the proposed word. Failure uses the actual observed word to repeat the equality and proposal logic. On success the low byte of the previous word selects a qword from the table at state+0x10 for the call at 0x5ce1f2b. These are static state transitions; the table object's type and the complete diagnostic contract are unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-packed-index-115/collect.py --out work/node115-snapshot-tcp-packed-index-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-packed-index-115/verify.py --out work/node115-snapshot-tcp-packed-index-check-fresh.json
```
