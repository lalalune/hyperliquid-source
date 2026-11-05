# RE-001 · Node #115 final initializer guard and mutex handoff

Component: foundation utilities, startup function map. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [initializer census](../RE-001-node115-init-array-census/README.md) maps the last slot to `0x635f320`. This packet follows the guard, first external call, and selected stores to the guard word.

## Observations

- Slot 167 at `0x63f3c00` has a relative relocation to `0x635f320`. The entry loads a 32-bit word at `0x64ffab4`, returns if it is zero, and tail-jumps to `0x634f0b0` otherwise. The word is in file-backed `.data` and its bytes encode 3 before loader or code effects.
- The helper passes `0x6509660` in `rdi` and calls PLT `0x63f17b0`. The jump slot at `0x64ee828` is bound to `pthread_mutex_trylock`. A nonzero return branches to `0x634f4d0`. The helper also tests the guard word again at `0x634f10e`.
- Stores at `0x634ef6a`, `0x634f2d0`, and `0x634f680` write 2, 1, and 0, respectively, to the same 32-bit address. The windows establish the address and values. They do not establish a transition order or show that all paths reach the stores.

The data and mutex linkage establish a bounded entry-to-helper handoff. The word's full semantics, other writers, helper ownership and all lock exit paths remain open. No implementation comparison or acceptance gate change is claimed.

## Reproduction

From the repository root with the pinned binary materialized, run using Python 3.11+, Capstone 5.0.9, and pyelftools 0.33:

```sh
python3 -B research/work-items/RE-001-node115-final-initializer-guard/inspect_guard.py
python3 -B research/work-items/RE-001-node115-final-initializer-guard/inspect_guard.py research/work-items/RE-001-node115-final-initializer-guard/evidence.txt
```

The first command derives [the transcript](evidence.txt) from the pinned ELF. Addresses are ELF VAs. The second command exits 1 at the digest check. Neither command executes captured code.
