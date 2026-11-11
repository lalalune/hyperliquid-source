# RE-012: recover node #115 thread alternate signal stack setup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The thread bootstrap reaches this helper with a zero selector. A zero global feature byte at 0x6500040 returns a null mapping. With the feature enabled and a zero selector, the helper queries pthread_self and pthread_getattr_np. Successful attribute lookup leads to pthread_attr_getguardsize, pthread_attr_getstack and pthread_attr_destroy. For nonzero guard size the range passed to 0x5ca2950 uses stack base minus and plus the guard size. A nonzero selector or failed initial attribute lookup skips that path.

The common path queries the alternate stack with sigaltstack and branches on flag bit 1 (SS_DISABLE). For a disabled stack it uses max(8192, getauxval(0x33)) as usable length and adds the global guard length. mmap64 reserves the combined size; mprotect applies protection zero to the leading guard range. The installed descriptor advances the base past that range, clears flags and retains only the usable length. The function then calls sigaltstack with the descriptor and returns its stack pointer. This packet documents the static allocation and setup path, including the exact imported functions, without assuming that installation succeeds at runtime.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-thread-signal-stack-115/collect.py --out work/node115-snapshot-thread-signal-stack-fresh
python3 -B research/work-items/RE-012-snapshot-thread-signal-stack-115/verify.py --out work/node115-snapshot-thread-signal-stack-check-fresh.json
```
