# RE-012: recover node #115 process descriptor receive control checks

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The existing native-process adapter evidence establishes the enclosing function's boundary. This packet recovers the receive-side control-message selection within it. The recvmsg loop retries return -1 on errno four and reloads the same message with flag 0x40000000. The successful path initializes the selected descriptor to -1.

Before accepting the control payload it requires a nonnull control pointer, a reported control length of at least 16, level and type dwords both equal to one, and a header length of exactly 20. It then loads the descriptor at control offset 16 and replaces the sentinel only for a nonnegative dword. These are observed gates, with no assertion that the enclosing spawn or receive path was executed.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-process-descriptor-receive-115/collect.py --out work/node115-snapshot-process-descriptor-receive-fresh
python3 -B research/work-items/RE-012-snapshot-process-descriptor-receive-115/verify.py --out work/node115-snapshot-process-descriptor-receive-check-fresh.json
```
