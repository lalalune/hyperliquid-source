# RE-012: map node #115 TCP pair detach lock and index selection

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the first callback in the TCP pair cleanup. The relocation at 0x64dfe40 names this body as its addend, distinct from the dynamic finalizer studied earlier.

The entry loads the allocation from +8. It chooses an embedded base at allocation+0x240 if the leading byte is zero, or +0x160 otherwise. Dword embedded+0x90 equal to 1,000,000,000 bypasses acquisition. Otherwise the fast acquisition at 0x5ceb00a compares byte embedded+0x50 against zero and writes one. The branch at 0x5ceb010 goes to the slow acquisition continuation on failure. The path after acquisition checks the +0x28 and +0x20 qwords against all ones. For the non-sentinel +0x20 branch the body XORs against embedded+0x60, ORs 0x3f, clamps unsigned at 0xffffffffe, then performs BSR, XOR with one, and a multiply-by-43 right shift by eight. The resulting index is scaled by 0x410 before adding the embedded+0x58 pointer.

The body also writes the all-ones +0x28 sentinel and contains a distinct qword CMPXCHG at object+0x40. The ordinary byte-release operation at 0x5ceb106 and unwind operation at 0x5ceb183 both address the saved embedded+0x50 pointer. These findings establish the local lock and indexed-state operations. Timer types and scheduler behavior remain inferred and are not claimed as recovered.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-timer-detach-115/collect.py --out work/node115-snapshot-tcp-timer-detach-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-timer-detach-115/verify.py --out work/node115-snapshot-tcp-timer-detach-check-fresh.json
```
