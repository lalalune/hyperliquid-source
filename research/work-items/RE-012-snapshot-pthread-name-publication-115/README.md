# RE-012: map node #115 pthread name selection and publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The entry takes a temporary reference with a locked increment and checks the thread-local qword at FS:-0x428. Its selected initialization path calls 0x5ca0e20 and publishes the object address plus 0x10 to that thread-local qword.

With a nonnull name pointer at object offset 0x18, the worker clears a 16-byte stack buffer and copies up to 15 bytes, using the recorded length at offset 0x20 minus one. With a null name pointer, it instead checks a nonzero global value against the qword at FS:-0x420 and uses the four bytes spelling `main` on equality. Otherwise it skips the name-setting call. The shared name path passes the stack buffer to pthread_setname_np with the result of pthread_self and does not branch on the setter's return. The name path and skip path join before the locked decrement of the temporary reference.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-pthread-name-publication-115/collect.py --out work/node115-snapshot-pthread-name-publication-fresh
python3 -B research/work-items/RE-012-snapshot-pthread-name-publication-115/verify.py --out work/node115-snapshot-pthread-name-publication-check-fresh.json
```
