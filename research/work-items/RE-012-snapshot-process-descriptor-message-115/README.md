# RE-012: recover node #115 process descriptor control message and retry

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This routine gets its own PID and passes it to syscall 0x1b2 with flags zero. The returned dword is staged at rbp-0x60. The message setup writes a 24-byte control length and a control header length of 20, then packs the two 32-bit values one and one immediately before the descriptor dword. These are the local control-message fields supplied to sendmsg on the input descriptor.

The send path uses flags zero and retries return -1 only when errno equals four. It drops the temporary packed error before reissuing the same message. A zero send result exits normally, while a nonzero successful result takes a separate diagnostic. This packet maps control-message construction and retry behavior without claiming a receiver implementation.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-process-descriptor-message-115/collect.py --out work/node115-snapshot-process-descriptor-message-fresh
python3 -B research/work-items/RE-012-snapshot-process-descriptor-message-115/verify.py --out work/node115-snapshot-process-descriptor-message-check-fresh.json
```
