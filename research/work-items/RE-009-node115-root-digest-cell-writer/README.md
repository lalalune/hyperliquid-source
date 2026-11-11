# RE-009: identify the node #115 root-digest cell writer

This packet follows the fallback path in [PR #5584](https://github.com/lalalune/hyperliquid-source/pull/5584) to resolve one explicit next question from [issue #3923](https://github.com/lalalune/hyperliquid-source/issues/3923): which selected helper writes the `.bss` object that the root-digest selector reads?

- Component: `abci` / RE-009 storage and state roots.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: repository `main` at `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Included: the selector's exact fallback call site, the fallback helper's CPUID leaf-0 entry, its selected writer/return block, the relocated pointer slot, and the destination's `.bss` extent.
- Excluded: full CPUID-bit meanings, all readers and writers of the object, caller-level serialization, runtime feature values, digest execution, and the full RE-009 component gate.

## Evidence and result

The selector fallback call at `0x160bf4b` goes through slot `0x64dfa68`; the authenticated `R_X86_64_RELATIVE` entry resolves that slot to `0x5cadd50`. That helper's FDE is `0x5cadd50..0x5cae3da`. At entry, it clears EAX and ECX and executes `CPUID` at `0x5cadd68`, issuing leaf 0 on that selected path.

In the helper's selected common return block, `0x5cae3a1` loads a pointer through slot `0x64dfa60`. Its relocation resolves to `0x6500098`, inside zero-fill `.bss`. The next three stores write qwords at offsets `0`, `8` and `0x10` from that pointer. The selected instructions form the first stored word as `r13 | rdi`; they then form two further words from `rdx`, `r13` and `rdi`. The block later sets RAX from `r13` and returns. Thus, the fallback's return value is not shown to be identical to the first qword it stores.

The three writes are separate ordinary `MOV` instructions. This packet does not establish whether every caller serializes helper execution, who else writes the object, or whether a concurrent reader can observe a partially updated object. It also does not assign symbolic meanings to the three qwords or to the CPUID-derived register values.

## Reproduction

From the repository root, with the authenticated node #115 LFS artifact materialized:

```sh
python3 research/work-items/RE-009-node115-root-digest-cell-writer/verify.py --self-test
(cd research/work-items/RE-009-node115-root-digest-cell-writer && shasum -a 256 -c MANIFEST.sha256)
```

The verifier checks the target digest, 29 instruction witnesses, FDE membership, file-backed `.text` bytes, the selector call edge, all three `R_X86_64_RELATIVE` relocations and the `.bss` bounds. Its negative controls reject a changed second-store offset and a changed cell relocation. It never executes the captured binary. Instruction rendering used Apple LLVM `llvm-objdump` 21.0.0; packet verification used Python 3.14.3.

`make doctor` reports missing GNU `objdump`/`readelf`, Java and Ghidra; the installed Apple LLVM disassembler was used for the bounded spans. This sparse checkout does not materialize all repository inputs, so full `make verify`, `make test` and `make catalogue-check` results are not claimed. The component gate remains false.

## Limits and next question

The packet proves a concrete writer and three destination offsets, not an exclusive writer census or a synchronization contract. It also does not map the stored values to the four digest implementations. A next bounded question is to identify the relevant CPUID-derived bits and compare them with the finalizer's implementation arms, retaining any unmapped cases.
