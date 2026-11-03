# RE-015: node #115 scratch-name value pair of the config-name accessor

- Component: RE-015 `global_constants` (component `constants`) — the value
  derived from the configured chain name by accessor `0x1568d80`.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: for each chain name an operator can configure, what pair does
  accessor `0x1568d80` return from the stored name tag byte, and for which
  names does that pair change?
- Observation: the pair is `(2, true)` for 77 of the 79 names and
  `(2, false)` for exactly the two scratch chains, `ScratchDummy` (tag 62)
  and `ScratchCron` (tag 63). The first component is the constant 2 for
  every name; only the boolean is name-dependent.
- No downstream semantic label for the pair, consumer semantics, complete
  caller recovery, #94 compatibility or reconstruction-gate claim.

## Why this item, in one paragraph

The operator action is configuring the chain name (`aws_name` in the static
config, e.g. `ScratchCron` for a scratch deployment) and confirming what the
node derives from it. The basis for the expected behaviour is the classifier
order published by open PRs #2042/#2054, independently re-derived here from
the 79-entry descriptor array at `0x6410ce8` with four anchor matches
(5 `NodeTestnet`, 18 `Ee`, 32 `SoloSandbox`, 33 `NvTestnet`), plus the
accessor's own bytes at `0x1568d80` in the digest-bound #115 packet. The
loss if this stays unrecorded: the reconstruction has zero record of this
accessor, and a reimplementation that treats the pair as name-independent —
or that reuses #94-era name positions — silently returns the wrong flag for
exactly the scratch chains, with no failing check anywhere to catch it. The
item is independent of the nearest open RE-015 PRs by repro case, not just
by filename: #2097's selector `0x15474d0` returns the 1.0/5.0
scheduled-observer factor and stores 0.1 × factor, and #2167's accessor
`0x154aa00` returns replica-bucket chain keys (byte 5 → key 2, byte 18 →
key 3, otherwise a missing sentinel); neither produces the
`(2, tag ∉ {62,63})` pair, and neither is altered by this accessor's result.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| config-name accessor | `0x1568d80..0x1568dd6` | 86 | 24 |
| defaults consumer (boundary) | `0x1506840..0x15069f2` | 434 | 85 |
| large consumer (boundary) | `0x15a3b90..0x15a6509` | 10,617 | not retained |

The measured denominator is **three complete FDEs, 11,137 bytes**. The
accessor and the small consumer have complete native exports retained; the
large consumer is retained only as its `frames.txt` line and its body hash
in `records.json` — a deliberate boundary choice, not a partial export.
Each retained export starts at its actual FDE entry and covers the complete
body. Native readelf confirmations, raw FDE/CIE records, file offsets and
body hashes are retained. All bodies are hash-pinned without normalization.
This is not a raw-equal or normalized cross-function/cross-release
equivalence claim.

## Trace stages

1. **Name → tag (context, owned by #2042/#2054).** The static-config
   initializer resolves the configured `aws_name` through the name
   classifier and stores the tag byte in the global configuration object
   (RELATIVE binding: slot `0x64e0918` → object `0x64f06c0`, pinned here) at
   offset **+0x48**; the initialization-guard dword sits at **+0x50**. This
   stage is cited context, not re-derived.
2. **Canonical tag order (re-derived).** The 79 (pointer, length)
   descriptor entries at `0x6410ce8` were reconstructed from `.rela.dyn`
   RELATIVE relocations plus inline lengths. All six anchors match the
   published order, including 62 `ScratchDummy` and 63 `ScratchCron`. The
   classifier rejects with 79 (per #2054), so the producible tag domain is
   exactly 0–78.
3. **Accessor: tag byte → pair (the item).** On the initialized fast path
   the accessor loads the config object via slot `0x64e0918`, checks the
   guard dword at +0x50 (the nonzero route goes through the generic once
   helper at slot `0x64df9f0` with `&[config+0x50]`, then rejoins), reads
   the tag byte at +0x48, and computes `setne` on `(tag & 0x7e) == 62`:
   `and al,0x7e` / `cmp al,0x3e` / `setne dl` / `mov al,2` / `ret`. The mask
   clears bits 0 and 7, so within the producible domain the compare fires
   for exactly the tag pair {62, 63}. The accessor performs no bounds check
   of its own; it trusts the stored byte.
4. **Where the value lives.** The accessor has **zero direct E8 callers**
   in `.text` (full scan, pinned) and exactly **one** RELATIVE relocation
   reference in `.rela.dyn`: cell **`0x64f01b0`** stores its address — a
   lazy-static slot, so the value is produced once through the generic
   lazy/once machinery and cached.

## Result summary

For every tag 0–78: `pair = (2, tag ∉ {62,63})`. The full 79-entry table
(tag, name, first, flag) is retained in `records.json`; the flag is false
at exactly tags 62 (`ScratchDummy`) and 63 (`ScratchCron`) and true for the
other 77 names. Over the full byte domain the mask algebra gives
`(tag & 0x7e) != 62`, false for {62, 63, 190, 191}; only 0–78 is
producible by the classifier.

## Explicit boundary and next question

The semantic label of the pair — what the constant 2 counts or limits, and
what the boolean enables — is **not** established by these bytes. The two
consumers are recorded as boundaries only (existence + body hash): FDE
`0x1506840..0x15069f2` reads the cell's state byte (compared to 2) and the
value dword at cell+8 on its input-absent route, and FDE
`0x15a3b90..0x15a6509` reads the cell's state bytes; both are large
multipurpose functions whose downstream use of the value is not closed
here. The consumer census behind this boundary covered FDEs in
`0x1400000–0x1800000`; a consumer outside that band referencing the cell
indirectly through a copied pointer would not appear. The classifier stage
itself remains the context of open PRs #2042/#2054. No gate is claimed.

Next question: resolve what the cached pair means downstream — what the
constant 2 counts or limits and what the boolean enables — by closing one
consumer's use of the cell+8 value.

## Reproduce and validation

From repository root with the materialized pinned capture and native GNU
tools on PATH:

```sh
python3 -B tools/scratch_pair_static.py --output research/work-items/RE-015-node115-scratch-name-pair
python3 -B -m unittest discover -s tests -p test_scratch_pair_static.py -v
(cd research/work-items/RE-015-node115-scratch-name-pair && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot; the
snapshot path is replaced with `<authenticated-node115>` in retained text.
Wrong-release, truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter the actual mask immediate, compare immediate,
result-constant immediate, tag-offset byte, descriptor name bytes,
descriptor/configuration/accessor relocations and the accessor FDE record;
each makes the checker reject the counterfactual. Below the full public
digest gate, this checks the named obligations, not arbitrary-byte error
detection or target execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and all
progress gates are preserved. No hosted-CI result or whole-component
completion is claimed.
