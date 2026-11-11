# RE-012: recover node #115 libc version delimiter scanner

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The host-version pair decoder calls this stateful delimiter scanner twice. State offset 0 is the buffer base; offsets 8, 16 and 24 supply the search bounds and cursor. The initial gate enforces cursor <= upper bound <= length. The delimiter length is read at +0x28, and the last delimiter byte at state +0x1f+length.

For delimiter lengths below five the short scan compares bytes directly. At 16 remaining bytes or more, the long scan aligns the address, checks pairs of qwords with a replicated final-byte mask, and falls back to scalar search at the candidate block. Finding the last byte advances the state cursor by one before deriving the candidate start as cursor minus delimiter length. The scanner tests borrow and the advanced upper bound before calling `bcmp` via the GLOB_DAT slot `0x64df9f8`. An exact match stores start and exclusive end in output qwords at +8 and +16 and writes tag 1. Normal exhaustion sets the cursor to the upper bound and returns tag zero.

The length-five-or-more arm uses a different long scan, calling the RELATIVE target `0x16818b0` via slot `0x64dfcb0` for 16 bytes or more. This packet anchors the dispatch, candidate advancement and result ABI without inferring that helper's implementation.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-libc-delimiter-search-115/collect.py --out work/node115-snapshot-libc-delimiter-search-fresh
python3 -B research/work-items/RE-012-snapshot-libc-delimiter-search-115/verify.py --out work/node115-snapshot-libc-delimiter-search-check-fresh.json
```
