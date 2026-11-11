# RE-012: recover node #115 epoll source registration event record

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The poller registration helper translates a derived interest byte into the packed epoll event. Bit zero selects base mask 0x80002001 instead of 0x80000000. Bit one contributes four, and twice the upper nibble is added separately. The helper writes that mask as a dword followed by an unaligned qword containing the allocation base plus 0x80.

The epoll_ctl call passes operation one, the epoll descriptor from owner +0x40, and the target descriptor read from its input pointer. A negative return captures errno as (errno << 32)|2 before attempting the byte lock used by the failure cleanup. This recovers per-source interest and token registration, distinct from the constructor's fixed wake descriptor record.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-epoll-registration-record-115/collect.py --out work/node115-snapshot-epoll-registration-record-fresh
python3 -B research/work-items/RE-012-snapshot-epoll-registration-record-115/verify.py --out work/node115-snapshot-epoll-registration-record-check-fresh.json
```
