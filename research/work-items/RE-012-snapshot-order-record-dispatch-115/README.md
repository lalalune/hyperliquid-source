# RE-012 snapshot order-record dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The order-record array writer calls 0x22b8e00 at 0x25381df. This packet resolves the selected record's direct and composite dispatch.

At entry, a low dword tag of 1 forwards RCX in RDI and tail-jumps to 0x23f6ec0. The other route checks the writer depth for all ones, increments it on the normal path and clears writer +0x20. It calls 0x2630fd0 at 0x22b8f39 with immediate arguments 42 and 20. Nonzero RAX reaches the shared return before the second value. A successful result sets the state byte, and the path emits a comma and line feed before the second dispatch at 0x22b9004. The same target as the direct arm, 0x23f6ec0, handles that second value. Its nonzero status skips finalization. On success the wrapper passes a stack descriptor whose first word is 0x0200 to 0x2331920 and returns zero. The original record variant names and child schemas remain open.

The full 710-byte FDE is retained. GNU, LLVM and Capstone agree on the instruction partition. GNU readelf confirms the extent. Replay rejects four changed windows, an import relocation mutation and two target-identity controls. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-order-record-dispatch-115/collect.py --out work/snapshot-order-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-order-record-dispatch-115/verify.py --out work/snapshot-order-dispatch-check-fresh.json
```
