# RE-012: map node #115 copy_file_range provider and chunk loop

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The worker at 0x5ca1670 reads availability byte 0x650008b. Value one immediately publishes tag two with a zero count. Otherwise it checks the requested count and then the copy_file_range import at 0x64eca00. A null import selects the syscall import at 0x64e06b8 with number 0x146. Both paths cap the first chunk at 0x40000000 bytes and apply the same cap to the remaining count on subsequent calls.

A nonnegative first return after an initial cache value of zero writes cache value two. Positive returns accumulate against the requested count. A later zero return can publish a successful partial count. Return -1 instead enters the shared errno dispatcher, with distinct state carried in from the initial and continuation calls. This packet maps the provider choice, chunking and cache transition in the copy_file_range worker. The separate splice/sendfile worker has its own provider and error policy.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-copy-file-range-worker-115/collect.py --out work/node115-snapshot-copy-file-range-worker-fresh
python3 -B research/work-items/RE-012-snapshot-copy-file-range-worker-115/verify.py --out work/node115-snapshot-copy-file-range-worker-check-fresh.json
```
