# RE-012: recover node #115 owner-recursive formatter transaction

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This formatter wrapper obtains an owner token from TLS at FS:-0x420. A zero token triggers a compare-exchange loop against the counter at 0x6500050, checks the all-ones exhaustion boundary, and caches the new token in TLS. Matching the lock owner takes the recursive arm and increments the depth at +12 unless it is already UINT32_MAX. A different owner attempts a 0-to-1 compare-exchange at +8, with a helper fallback on failure, then installs the owner and initializes depth to one.

Under the lock the wrapper passes descriptor 0x64c2e90, the forwarded arguments and a stack adapter to the formatting target (RELATIVE slot 0x64df6f0, addend 0x1680500). It reconciles the low status byte with the stack error slot and releases one nesting level. The final release zeros the owner and exchanges the lock word with zero. Only a prior word of two takes the wake arm, which passes syscall number 0xca, operation 0x81 and count one. The unwind paths call 0x5c74d00 before resuming. This packet maps the guarded formatter transaction and leaves the formatter and contended acquisition bodies as boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-owner-reentrant-format-115/collect.py --out work/node115-snapshot-owner-reentrant-format-fresh
python3 -B research/work-items/RE-012-snapshot-owner-reentrant-format-115/verify.py --out work/node115-snapshot-owner-reentrant-format-check-fresh.json
```
