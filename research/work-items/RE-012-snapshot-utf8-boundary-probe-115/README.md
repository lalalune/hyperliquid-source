# RE-012: recover node #115 two-sided UTF-8 boundary probe

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This wrapper diagnoses a candidate UTF-8 byte boundary. It first subtracts the offset from total length with a borrow check. At an in-range offset it validates up to four bytes starting there. A successful validation or a failure with nonzero valid-prefix length returns immediately.

If the forward probe fails at its first byte, the wrapper checks preceding spans ending at the candidate offset. It starts with width two and caps the search at min(offset,4). A preceding span that the shared validator accepts returns normally. If none is accepted, the wrapper passes the candidate offset to a separate formatter and diagnostic call at 0x5ca4775. The out-of-range offset goes directly to the diagnostic at 0x5ca47ac. This packet distinguishes the wrapper's two-sided probes from the shared validator's byte-level rules.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-utf8-boundary-probe-115/collect.py --out work/node115-snapshot-utf8-boundary-probe-fresh
python3 -B research/work-items/RE-012-snapshot-utf8-boundary-probe-115/verify.py --out work/node115-snapshot-utf8-boundary-probe-check-fresh.json
```
