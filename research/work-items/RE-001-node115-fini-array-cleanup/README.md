# RE-001 · Node #115 finalizer entry and guarded cleanup

- Component: foundation utilities, startup and teardown function map.
- Input: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. The [initializer census](../RE-001-node115-init-array-census/README.md) established the slot. This packet examines its target.

## Observations

1. `DT_FINI_ARRAY` identifies VA `0x63f36c0` with size 8. The zeroed slot receives `R_X86_64_RELATIVE` with addend `0x14193a0`. `DT_FINI` names a separate entry.
2. The entry begins with `endbr64`. At `0x14193a4` it checks byte `0x64ffe40` in `.bss` and returns immediately when nonzero. On the other path it tests GOT slot `0x64df478`. A nonzero slot leads to a call through PLT entry `0x63f0a40` with the value loaded from `0x64efa20`. Both the tested GOT slot and the PLT jump's slot have relocations naming `__cxa_finalize`. The argument cell has a RELATIVE relocation with its own address as the addend.
3. Both paths through the body call `0x1419330` before setting the guard byte to 1. At that helper, two RIP-relative address calculations both yield `0x64efa20`. The comparison therefore takes the return branch. The alternative indirect jump uses a slot with a relocation naming `_ITM_deregisterTMCloneTable`.
4. No `.eh_frame` FDE covers `0x14193a0`. The evidence lists the contiguous decoded bytes through both returns, with the end of the window immediately following the second return. The `.text` byte scan found no E8/E9 rel32 candidate targeting the entry. The same scan finds the observed call at `0x14193c7` when pointed at the helper.

## Inference and limits

The flag implements a guard against repeated cleanup after the first invocation completes. The sequence is consistent with compiler-generated C runtime teardown. No original local symbol or source revision was established. The E8/E9 scan covers direct near calls and unconditional near jumps with a 32-bit displacement in `.text`. Indirect edges, other branch encodings and other executable sections are outside that denominator. The separate `DT_FINI` routine remains to be mapped. No implementation comparison or component gate change is claimed.

## Reproduction

Run from the repository root with the pinned Git LFS artifact present. The evidence was generated with Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. All addresses are ELF VAs unless labeled file offsets.

```sh
python3 -B research/work-items/RE-001-node115-fini-array-cleanup/inspect_fini.py
python3 -B research/work-items/RE-001-node115-fini-array-cleanup/inspect_fini.py research/work-items/RE-001-node115-fini-array-cleanup/evidence.txt
```

The first command reproduces [the evidence transcript](evidence.txt). The second is a negative control and exits 1 with a digest mismatch before parsing ELF. The target is read only.
