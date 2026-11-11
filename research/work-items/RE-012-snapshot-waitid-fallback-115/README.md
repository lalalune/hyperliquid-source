# RE-012: recover node #115 waitid status conversion and descriptor fallback

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The descriptor-backed child status helper calls waitid with selector three. On a non-error return a zero PID field produces the pending result. A nonzero PID field dispatches through a six-entry table indexed by the status code minus one. The selected arms include shifting the status by eight, applying 0x7f or 0x80, and emitting 0xffff.

Failure captures errno before any fallback. Only errno ten reaches ioctl request 0xc040ff0b with a zeroed stack request and leading qword eight. Successful ioctl returns the dword from rbp-0x3c as a present status. Failed ioctl retains the original waitid errno payload for the caller and drops the temporary ioctl error. This distinguishes the descriptor-backed status decoder from its caller's caching and waitpid branch.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-waitid-fallback-115/collect.py --out work/node115-snapshot-waitid-fallback-fresh
python3 -B research/work-items/RE-012-snapshot-waitid-fallback-115/verify.py --out work/node115-snapshot-waitid-fallback-check-fresh.json
```
