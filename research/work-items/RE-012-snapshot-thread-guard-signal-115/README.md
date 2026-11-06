# RE-012: recover node #115 signal handler guard-range lookup and fallback

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The handler uses the current thread's errno pointer as the registry owner key. The acquisition attempt is bounded, compares the owner with the same pointer on failure and executes PAUSE before retrying. Exhausting the spin budget selects a direct 27-byte diagnostic write to descriptor two. The write path advances the buffer on a positive partial result and retries errno four.

The registry path looks up the current owner key, then accepts an address only when lower <= address < upper, comparing against the stored qwords at +0x48 and +0x50 relative to the scan cursor. The hit arm reads the stored thread ID and name pointer and length, with a nine-byte default when the pointer is null. The non-hit path clears the owner slot before building a zeroed signal-action record. The fallback calls sigaction for the original signal number with no old-action output. This packet maps the reader and fallback, complementing the separately recovered insertion and deletion functions.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-thread-guard-signal-115/collect.py --out work/node115-snapshot-thread-guard-signal-fresh
python3 -B research/work-items/RE-012-snapshot-thread-guard-signal-115/verify.py --out work/node115-snapshot-thread-guard-signal-check-fresh.json
```
