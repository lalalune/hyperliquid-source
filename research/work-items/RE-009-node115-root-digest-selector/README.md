# RE-009: node #115 root-digest implementation selector

This packet closes the selector-production question explicitly left open by the [node #115 outer hash-mode packet](../RE-009-node115-abci-root-hash-mode/README.md) and [digest dispatch packet](../RE-009-node115-root-digest-final-dispatch/README.md). It answers one bounded step from [issue #3923](https://github.com/lalalune/hyperliquid-source/issues/3923): which byte the selected root-digest setup path stores as its implementation selector, and how the selector obtains the word it tests.

- Component: `abci` / RE-009 storage and state roots.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `main` at `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No unlicensed reference source was used.
- Included: the complete selector FDE `0x160bee0..0x160bf68`, its selected root-setup caller edges, the selector's relocated data cell and fallback call target, and the fallback routine's CPUID entry witness.
- Excluded: the producer or synchronization of the `.bss` cell, the full fallback routine, symbolic meanings for its tested bits, runtime CPU state, digest execution, and the full RE-009 component gate.

## Result

The root-setup function calls selector `0x160bee0` through relocation slot `0x64df488`. Its return byte in `AL` is stored at `[rsp+0xfb]`; with the surrounding context base at `rsp+0x90`, that is context offset `+0x6b`. The existing hash-mode packet identifies `+0x6b` as the implementation selector consumed by the digest preparation path.

The selector loads a pointer through `0x64dfa60`, relocated to `.bss` address `0x6500098`. It then reads a qword from that cell. Each predicate stage reloads the cell; when the loaded qword is zero, that stage instead calls through `0x64dfa68`, relocated to `0x5cadd50`. The fallback routine's entry sets EAX and ECX to zero before `CPUID` at `0x5cadd68` (leaf 0). This is consistent with a CPU-capability selection path, but this packet does not decode the full helper or name the tested bits.

The exact predicate order, over successive effective reads `w0` through `w3`, is:

```text
w0 = cell-or-fallback()
if bit 19 of w0 is set:
    w1 = cell-or-fallback()
    if bit 25 of w1 is set: return 4
w2 = cell-or-fallback()
if bit 15 of w2 is set: return 3
w3 = cell-or-fallback()
return 1 + bit 10 of w3
```

The cell-or-fallback operation means: read the `.bss` cell, and call the fallback only if that read is zero. The separate reloads matter: the simplified formula `if bit19 and bit25 then 4, else if bit15 then 3, else 1+bit10` describes only a stable-word case. If the cell or fallback result changes between reads, the machine code evaluates the predicates against different words. The output is one of bytes 1 through 4; the bit meanings and runtime-selected value remain unresolved.

## Reproduction

Run from the repository root with the authenticated node #115 LFS artifact materialized:

```sh
python3 research/work-items/RE-009-node115-root-digest-selector/verify.py --self-test
(cd research/work-items/RE-009-node115-root-digest-selector && shasum -a 256 -c MANIFEST.sha256)
```

The verifier checks the full target digest, all 46 selector instruction rows, caller/provider witnesses, FDE membership, file-backed `.text` bytes, four branch destinations, all four fallback call edges, and the three relevant `R_X86_64_RELATIVE` relocations. It rejects an altered selector-mask byte and an altered provider relocation. It does not execute the target. The instruction renderings were captured with Apple LLVM `llvm-objdump` 21.0.0 using Intel syntax; Python 3.14.3 was used for the verifier.

Local environment checks: `make doctor` reported that GNU `objdump`/`readelf`, Java and Ghidra are unavailable. Apple LLVM's `llvm-objdump` 21.0.0 was available and decoded the selected x86-64 spans. This sparse checkout did not contain the repository-wide inputs needed to run the full `make verify`, `make test` and `make catalogue-check` suites; those results are not claimed here. The focused packet verifier and manifest check are the evidence for this packet.

## Limits and next step

This is static selector evidence, not a completed root algorithm or a component gate. It does not prove the `.bss` cell is a cache, identify who initializes it, establish a memory-order contract, or name the CPUID-derived bits. The next bounded question is to trace the concrete writer or fallback-to-cell publication path and map the selected feature bits to the four digest implementations, preserving the unverified cases.
