# RE-012: recover node #115 directory entry iterator advancement

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This routine advances a directory iterator backed by the import `readdir64` at GLOB_DAT slot `0x64ec9e0`. An already-complete flag at iterator +8 bypasses the import. The active path gets the thread-local errno pointer through `0x64dffc8`, zeros it before both the first read and retry, and passes the stream stored at shared state +0x28. A null return sets the completion flag. Errno zero returns the empty result; nonzero errno is shifted left 32 and ORed with tag 2 for the error payload.

The filter compares name length and skips exact one-byte dot or two-byte dot-dot entries. The retained path saves the entry byte at +0x12 and copies name bytes through the `memcpy` slot `0x64df508` after allocation; the regular name path increments the measured length to include the terminator. Before returning, it increments the shared owner count with a locked instruction and stores the owner, copied name fields, entry qword, and entry byte. This static window covers advancement, termination and returned ownership.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-directory-entry-step-115/collect.py --out work/node115-snapshot-directory-entry-step-fresh
python3 -B research/work-items/RE-012-snapshot-directory-entry-step-115/verify.py --out work/node115-snapshot-directory-entry-step-check-fresh.json
```
