# RE-012: recover node #115 thread bootstrap and payload ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The entry retains the shared object with a locked increment and gates installation of the current-thread metadata. FS:-0x428 must initially be clear. FS:-0x420 may be zero, in which case the object token at +0x10 is installed, or it may already equal that token. The accepted path calls the setup helper and publishes the address of the token field at FS:-0x428.

A nonnull name pointer at +0x18 supplies the thread name. The copy count is min(stored field at +0x20 minus one, 15), into a zero-initialized 16-byte buffer. If the name pointer is null, a nonzero matching global token selects a four-byte literal; other null cases skip naming. The external calls are pthread_self through 0x64eaf20 and pthread_setname_np through 0x64eca30.

The tail extracts the payload and its table from the outer record, drops the temporary shared reference, and frees the 24-byte outer record. It then invokes table +0x18 on the payload and consults the table's size and alignment fields before optional payload deallocation. This packet maps the thread bootstrap and transferred payload lifecycle without assigning a higher-level node role to the callback.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-thread-bootstrap-115/collect.py --out work/node115-snapshot-thread-bootstrap-fresh
python3 -B research/work-items/RE-012-snapshot-thread-bootstrap-115/verify.py --out work/node115-snapshot-thread-bootstrap-check-fresh.json
```
