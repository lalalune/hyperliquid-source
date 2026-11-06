# RE-012: recover node #115 local socket address query and result ABI

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The local-address query calls getsockname via GLOB_DAT slot 0x64ec880 with a zeroed 128-byte buffer and an initial length of 128. It dispatches on the returned family and checks the returned length before reading fields: IPv4 requires at least 16 bytes, IPv6 at least 28.

IPv4 emits tag zero, the four address bytes at +2 and byte-swapped port at +6. IPv6 emits tag one, the 16 address bytes starting at +2, the raw flow and scope words at +0x14 and +0x18, and byte-swapped port at +0x1c. A failed syscall packs errno with low bits two and uses output tag two. Unsupported family also uses that output tag but stores a fixed descriptor. Short known-family buffers take separate diagnostic branches. The packet recovers the local-address query and result ABI.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-socket-local-address-115/collect.py --out work/node115-snapshot-socket-local-address-fresh
python3 -B research/work-items/RE-012-snapshot-socket-local-address-115/verify.py --out work/node115-snapshot-socket-local-address-check-fresh.json
```
