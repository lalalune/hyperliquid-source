# RE-012: map node #115 resolver hints and system error path

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: bind the short address fallback's libc call and system-error encoding. The call at 0x5c81c52 uses slot 0x64ec6d8, relocated to getaddrinfo@GLIBC_2.2.5. It passes the original NUL-terminated input as node, null service, a zeroed 48-byte hints area with dword +8 set to one, and a pointer to a zero-initialized result slot. A zero status goes to 0x5c81cac. On the selected nonzero path the code saves the status, invokes 0x5ca19c0, then tests the saved status against -11. The matching branch obtains a dword through slot 0x64dffc8 and encodes it in the upper 32 bits with low bits set to two. No resolver is executed by this packet.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-resolver-hints-115/collect.py --out work/node115-snapshot-address-resolver-hints-fresh
python3 -B research/work-items/RE-012-snapshot-address-resolver-hints-115/verify.py --out work/node115-snapshot-address-resolver-hints-check-fresh.json
```
