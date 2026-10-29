# RE-014: Which #94 functions survive into #115, and do the catalogue's missing paths match the binaries?

- Component ID: none (binary-wide release drift; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
  Every row carries both coordinates; no #94 address is reused for #115.
- Depends on: RE-001 (PR #2, head `191b83b`). Function extents come only from
  `tools/fde_extents.fde_extents`; this packet has no FDE decoder of its own.
- Claim status: observation (byte and instruction equality, catalogue path
  strings); inference (`changed` pairings); unresolved (unmatched rows)
- Scope included: every `.text` FDE extent in both releases, and the
  `absent115` / `added115` path lists in `research/catalogue/components.json`.
- Scope excluded: behaviour, source attribution, `.rodata` contents, code with
  no FDE, split hot/cold reassembly. RE-014 is **not** complete.

## Reproduce

Platform: Debian (box), Python 3.13, GNU objdump 2.44 (Debian). Static only;
no captured binary is executed. About 4 minutes and a single objdump stream
per binary.

```sh
make verify
make drift            # writes work/drift/node-94-115-drift{.tsv,.json} and -paths.json
python3 -I -B research/work-items/RE-014-release-drift/verify.py
python3 -O -B research/work-items/RE-014-release-drift/verify.py
python3 -I -B research/work-items/RE-014-release-drift/mutation_controls.py
python3 -I -B research/work-items/RE-014-release-drift/crosscheck.py --tsv work/drift/node-94-115-drift.tsv
python3 -m unittest tests.test_release_drift
```

`tools/release_drift.py` verifies both artifact digests, takes `.text` FDE
extents from RE-001, disassembles `.text` once per binary with
`objdump -d --no-show-raw-insn -w -j .text`, and refuses to write into a
non-empty output directory. It fails closed on an extent with no decoded
instruction. `verify.py` refuses to run unless the objdump version string
matches the pinned one, because disassembly text is the fingerprint input.

### Fingerprints and masking

Each extent gets two hashes:

- **raw**: SHA-256 of its file bytes.
- **masked**: SHA-256 of its instruction text with only address-like operands
  masked. Every mask is counted (`masked_operands` in the summary):

| Masked operand | Replaced by | #94 | #115 |
| --- | --- | ---: | ---: |
| Direct branch/call to an FDE start | `@fde` | 496,825 | 558,403 |
| Direct branch/call into `.plt` | `@plt` | 107,390 | 113,386 |
| Direct branch/call elsewhere outside the extent | `@unknown` | 7,422 | 7,421 |
| RIP-relative displacement | `RIP` | 884,000 | 955,207 |
| Immediate inside the mapped image range | `ADDR` | 291,921 | 344,601 |

Branches inside the extent keep their extent-relative offset. Other
immediates, stack offsets and register choices are compared verbatim. The
target kind stays in the text, so retargeting a call from a function to the
PLT is a change. Only `call @fde` targets are used as call-graph edges;
unresolved targets are never guessed.

### Pairing and classes

Pairs are seeded by a hash unique on both sides (raw first, then masked), then
grown through the call graph: a callee or caller of a paired function is paired
when its masked hash is unique within that neighbourhood, or by call position
when both callee lists have the same length and the sizes are within 2×.

| Class | Meaning | Claim |
| --- | --- | --- |
| `identical` | paired, raw bytes equal | observation |
| `moved_only` | paired, raw differs, masked equal | observation (masked-only match) |
| `changed` | paired by call-graph position, masked differs | inference |
| `equivalent_unpaired` | a masked twin exists on the other side, not uniquely pairable | observation |
| `unmatched_94` / `unmatched_115` | no pairing | unresolved |

## Evidence

Generated outputs (byte-identical across two runs with `PYTHONHASHSEED=1`
under `-I` and `PYTHONHASHSEED=987` without; SHA-256):

| File | Rows | SHA-256 |
| --- | ---: | --- |
| node-94-115-drift.tsv | 237,812 | `36716f72d421deb172c4f54634e20c321d441b8655c6e669ff6617e8388229dd` |
| node-94-115-drift.json | — | `ae7aefd718bddc40a1ebf23c22e8b10916605be2ef7cfafcef036800a557ea6e` |
| node-94-115-paths.json | 63 | `2510fca9ee11e3174fec9407377de8f1ad8e3a7254b96623d3e43a49e6441f9b` |

The 14 MB TSV stays in ignored `work/`. The summary and path results are
retained here, and `validation.json` pins all three hashes plus every count
below.

| Observation | #94 | #115 |
| --- | ---: | ---: |
| `.text` FDE extents (= RE-001 FDE records) | 121,299 | 135,313 |
| Instructions decoded inside extents | 15,730,149 | 18,827,581 |
| `identical` rows / bytes | 2,028 / 397,057 | 2,028 / 397,057 |
| `moved_only` rows / bytes | 14,877 / 7,868,106 | 14,877 / 7,868,106 |
| `changed` rows (inferred pairs) / bytes | 1,895 / 2,118,246 | 1,895 / 2,132,918 |
| `equivalent_unpaired` rows / bytes | 45,697 / 6,400,714 | 48,543 / 7,144,962 |
| `unmatched` rows / bytes | 56,802 / 52,613,292 | 67,970 / 65,118,374 |

- **Byte-equal code is small:** 16,905 functions (8.27 MB of #94's
  69.40 MB of FDE-covered code) pair with equal masked text; only 2,028 of
  them are byte-identical. Most surviving code moved and only its address
  operands differ.
- **Duplicates dominate the remainder:** 94,240 rows have a masked twin across
  releases but no unique pairing (generic instantiations and small thunks),
  so they are counted, not paired.
- **Catalogue paths agree with the binaries:** a path matches only as
  `<crate>/src/<file>` at a path boundary (#94 embeds absolute
  `/home/ubuntu/hl/code_Mainnet/…` paths, #115 relative ones). All 28
  `absent115` paths occur in #94 and not #115; all 35 `added115` paths occur
  in #115 and not #94 (`node-94-115-paths.json`). A bare suffix match would
  have hit std's `/src/time.rs`; the boundary test is a unit-tested negative
  control.
- **Independent cross-check:** `crosscheck.py` takes every 97th
  `identical`, `moved_only` and `changed` row (21 / 154 / 20). It slices
  bytes using `readelf -S` offsets rather than the tool, and disassembles
  each function separately with `objdump --start-address/--stop-address`.
  Every sampled `identical` row has equal bytes; every `moved_only` row has
  differing bytes, equal size and equal disassembly once every hex number is
  masked (a wider mask than the tool's); every `changed` row has differing
  bytes. 0 contradictions.

## Implementation and comparison

No Rust implementation; deterministic offline tooling and static observation.

- `mutation_controls.py` assembles a C→A→B call chain, disassembles real
  bytes with objdump and mutates the #115 side. The checks are: moving B
  gives `moved_only` for A; changing an instruction, a constant, or a call
  target (to non-FDE code or to the PLT) gives `changed`; an added function
  gives `unmatched_115`; no mutation gives all `identical`.
- `tests/test_release_drift.py` adds negative controls: constants and stack
  offsets outside the image are not masked; duplicate masked hashes are never
  paired; the 2× size bound rejects a 201-byte partner of a 100-byte function;
  a path only behind a non-boundary byte does not match; an empty extent
  fails closed; output bytes are independent of input order and of
  `PYTHONHASHSEED` (0, 1, 4242).
- Five deliberate tool mutations each fail the unit tests: masking every
  immediate, merging branch-target kinds, dropping call-position pairing,
  dropping intra-extent branch offsets, and not masking RIP displacements.
  The first three also fail `mutation_controls.py`.
- `verify.py` rebuilds into a temporary directory and checks the three output
  hashes, the retained files, 11 pinned summary values, the cross-check result
  and the mutation controls. It uses no `assert` and passes under `-I -B`
  and `-O -B`.

## Results and limitations

What this does not claim:

- **Not behavioural equivalence.** `moved_only` compares instruction text
  with addresses masked. Data behind a RIP-relative or image address is not
  compared, so a changed `.rodata` constant can still be `moved_only`.
- **`changed` pairs are inferred** from call-graph position and size, not
  proven to be the same source function.
- **Unmatched is not added or removed.** A function can be unmatched because
  it changed and has no paired neighbour, was inlined differently, or was
  split differently.
- **An FDE is not a function.** Split hot/cold parts are separate rows and code
  without unwind data is absent (RE-001 limits apply). objdump's linear sweep
  can mis-decode data inside `.text`.
- **Path rows describe embedded strings only,** not code ownership. No
  progress gate is requested; every component gate stays false.

Optional, not required by this packet: REA 6.8.0 `rea-doctor` and
`rea-smoke` pass statically for both releases. A Ghidra function-matching pass
could check a sample of `changed` pairs independently.

Next question: for the 1,895 inferred `changed` pairs, which differ only in
`.rodata`-referenced data or inlining? Which of the 56,802 unmatched #94
functions sit under the 28 `absent115` source paths?
