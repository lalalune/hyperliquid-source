# RE-001: node #115 FDE census for `.text` band `0x3a80000..0x3ac0000`

- Component allocation: `foundation` (the existing work-allocation label; not validated component ownership).
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Scope: FDEs whose entry VA starts in this 256 KiB half-open `.text` band; exact FDE ranges, raw FDE records, body hashes, and native instruction counts.
- Exclusions: no reconstruction, behavior, source names, full-module denominator, or progress-gate claim.

## Why this band

The merged [band 3a census, PR #2940](https://github.com/lalalune/hyperliquid-source/pull/2940) names extension to a neighboring band as its next step after checking claims. The open [band 3b census, PR #5064](https://github.com/lalalune/hyperliquid-source/pull/5064) covers only `0x3a40000..0x3a80000`. This packet measures the immediately following, non-overlapping start range `0x3a80000..0x3ac0000`; it preserves the starts-only rule so an FDE starting in this band can end beyond its upper bound.

## Reproduce

From the repository root with the pinned LFS target materialized:

```sh
python3 -B tools/foundation_fde_band3c_census.py --write
python3 tests/test_foundation_fde_band3c_census.py
python3 -B tools/foundation_fde_band3c_census.py
```

The checker verifies the target digest, parses the file-backed `.text` and `.eh_frame` sections using the repository's static ELF/FDE parsers, and disassembles each selected FDE with `objdump`. It counts only address rows with decoded instruction text; address-prefixed byte-only continuation rows add to decoded-byte coverage but not the instruction count. Each FDE must decode exactly its `end - start` bytes. The saved tool identity is in `tools.json` (this capture was produced with Apple LLVM objdump 21.0.0). No command executes or copies the node.

## Results

The selected band contains **214** complete, unique, disjoint FDE ranges. The first starts at `0x3a81220`; the last starts at `0x3abf4c0` and ends at `0x3ac0177`, crossing the band boundary while remaining within `.text`. The smallest selected body is `[0x3aa8840,0x3aa887f)`, 63 bytes. `evidence.json` records every range, exact body SHA-256, instruction count, and decoded-byte count. `frames.txt` retains the raw FDE records; `window.txt` retains the smallest body's prologue bytes and disassembly excerpt.

## Limits

An FDE is an unwind-described range, not a validated logical function boundary. The band supplies no whole-module denominator, function ownership, semantics, or equivalence claim. Its `foundation` component label is only the existing work-allocation label. The target was read as data and never executed or copied. All component gates remain unchanged.
