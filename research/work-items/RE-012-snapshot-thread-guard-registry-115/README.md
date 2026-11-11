# RE-012: recover node #115 thread guard registry update and root initialization

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The signal-stack setup passes the lower and upper guard addresses to this routine. The entry obtains a thread ID through gettid if the imported slot is available and through syscall 0xba otherwise. It obtains optional name data from the FS:-0x428 record or, for a matching main-thread token, allocates the four-byte literal main.

The registry transaction acquires the 32-bit word at 0x6500028 and then claims a second global owner slot at 0x6500030 using the thread's errno pointer. The retry compares against that same pointer before yielding. In the existing-tree path, a node's u16 count at +0x21a bounds a 40-byte-stride value scan and pointer-array descent at +0x220. The matching-key arm replaces five qwords: name pointer, name length, lower bound, upper bound and sign-extended thread ID. If the previous name pointer and length are both nonzero it releases that old buffer. The empty-root path allocates 0x220 bytes, writes the first key and value and initializes count one.

The common completion clears the second owner slot, exchanges the outer lock with zero and branches to the wake path for prior state two. This packet maps the selected update and empty-root paths. Insertions into a populated tree and node splits remain outside the recovered semantics.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-thread-guard-registry-115/collect.py --out work/node115-snapshot-thread-guard-registry-fresh
python3 -B research/work-items/RE-012-snapshot-thread-guard-registry-115/verify.py --out work/node115-snapshot-thread-guard-registry-check-fresh.json
```
