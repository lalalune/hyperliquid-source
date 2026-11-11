# RE-012: map node #115 waiter publication and lock release ordering

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: identify waiter publication ordering in 0x5bb4670. Prior entry-word work identifies this family member's common lookup but does not decode its selected insertion path.

The routine first writes one to waiter+0x20. If bucket+8 is null it installs the waiter as head, otherwise it writes the waiter into previous tail+8 using bucket+0x10. Both paths replace bucket+0x10. It then subtracts one from the bucket word using locked XADD. The pre-subtraction value selects an alternate continuation if it is at least 4 and bit 1 is clear. The direct continuation separately tries a locked byte exchange of expected 1 to 0 on the pointer saved at rsp+8. After success it loads waiter+0x20 and compares ebp with 1,000,000,000 before choosing the next wait branch. The two lock words and their order are distinct. This packet does not claim to recover the timeout continuation or identify all callers.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-waiter-enqueue-115/collect.py --out work/node115-snapshot-lock-waiter-enqueue-fresh
python3 -B research/work-items/RE-012-snapshot-lock-waiter-enqueue-115/verify.py --out work/node115-snapshot-lock-waiter-enqueue-check-fresh.json
```
