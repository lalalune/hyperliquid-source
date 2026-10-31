# RE-014: Which #94 functions survive into #115, and do the catalogue's missing paths match the binaries?

- Component ID: none (binary-wide release drift; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
  Every row carries both coordinates; no #94 address is reused for #115.
- Depends on: RE-001 (PR #2, head `191b83b`). Function extents come only from
  `tools/fde_extents.fde_extents`; this packet has no FDE decoder of its own.
- Claim status: observation (byte and instruction equality, catalogue path
  strings); inference (`changed` and `duplicate_ordered` pairings); unresolved
  (unmatched rows)
- Scope included: every `.text` FDE extent in both releases, and the
  `absent115` / `added115` path lists in `research/catalogue/components.json`.
- Scope excluded: behaviour, source attribution, `.rodata` contents, code with
  no FDE, split hot/cold reassembly. RE-014 is **not** complete.


## Portability (objdump)

Mutation controls (`mutation_controls.py`) use a **pure-Python** AT&T decoder for
the tiny x86-64 opcode subset they assemble. They do **not** shell out to
`objdump`, so they pass on macOS under LLVM objdump and on Linux under GNU
objdump alike.

`tools/release_drift.py` fingerprints still require **GNU** objdump (AT&T text
is the evidence input). `gnu_objdump()` inspects `objdump --version` for `GNU`
and returns `(None, reason)` otherwise. `verify.py` and `crosscheck.py` then
**SKIP with an explicit reason** (exit 2 / SystemExit) — they do **not** PASS
when the GNU verifier is unavailable. Retained JSON evidence in this packet is
unchanged from the closed PR #9 drift run under GNU objdump 2.44.
Drift-verify is only authoritative in the CI container (pinned GNU objdump 2.44); elsewhere it reports SKIPPED.

## Reproduce

Platform: Debian (box), Python 3.13, GNU objdump 2.44 (Debian). Static only;
no captured binary is executed. About 4 minutes and a single objdump stream
per binary.

```sh
make verify
make drift            # writes work/drift/node-94-115-drift{.tsv,.json} and -paths.json
python3 -I -B research/work-items/RE-014-release-drift/verify.py
python3 -O -B research/work-items/RE-014-release-drift/verify.py
python3 -I -B research/work-items/RE-014-release-drift/mutation_controls.py  # pure-Python; no objdump
python3 -O -B research/work-items/RE-014-release-drift/mutation_controls.py
python3 -I -B research/work-items/RE-014-release-drift/independent_verify.py
python3 -I -B research/work-items/RE-014-release-drift/crosscheck.py --tsv work/drift/node-94-115-drift.tsv
# optional, needs the independent cross-check CSV (not in the repo):
python3 -I -B research/work-items/RE-014-release-drift/reconcile.py work/drift/node-94-115-drift.tsv classification.csv
python3 -m unittest tests.test_release_drift
```

`tools/release_drift.py` verifies both artifact digests, takes `.text` FDE
extents from RE-001, disassembles `.text` once per binary with
`objdump -d --no-show-raw-insn -w -j .text`, and refuses to write into a
non-empty output directory. It fails closed on an extent with no decoded
instruction, and unless each binary is ET_DYN (PIE) with no `DT_TEXTREL` and
no `DF_TEXTREL`: that is what makes it safe to compare immediates verbatim. `verify.py` refuses to run unless the objdump version string
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

Branches inside the extent keep their extent-relative offset. Immediates,
stack offsets and register choices are compared verbatim. In a PIE without
text relocations every image address in code is RIP-relative, so an immediate
is a constant. An earlier draft also masked immediates inside the mapped image
range; because these images map from `0x2e0` that hid real constants such as
frame sizes (`sub $0x348,%rsp` vs `sub $0x3d8,%rsp`), and the reconciliation
below caught it. The
target kind stays in the text, so retargeting a call from a function to the
PLT is a change. Only `call @fde` targets are used as call-graph edges;
unresolved targets are never guessed.

### Pairing and classes

Pairs are seeded by a hash unique on both sides (raw first, then masked), then
grown through the call graph: a callee or caller of a paired function is paired
when its masked hash is unique within that neighbourhood, or by call position
when both callee lists have the same length, the sizes are within 2× and
neither body has a masked twin anywhere on the other side.

Leftover functions with equal masked bodies (duplicate groups) are then paired
by address order, but only inside one gap between anchors: the anchors are the
longest chain of existing pairs that increases in both releases, and a group
is paired in a gap only when that gap holds the same number of its members on
each side. These pairs get their own class because which copy pairs with which
is an inference.

| Class | Meaning | Claim |
| --- | --- | --- |
| `identical` | paired, raw bytes equal | observation |
| `moved_only` | paired, raw differs, masked equal | observation (masked-only match) |
| `changed` | paired by call-graph position, masked differs | inference |
| `duplicate_ordered` | masked equal, paired by order within one anchor gap | inference (pairing); observation (masked equality) |
| `equivalent_unpaired` | a masked twin exists on the other side (possibly already paired), no pairing of its own | observation |
| `unmatched_94` / `unmatched_115` | no pairing and no masked twin | unresolved |

## Evidence

Generated outputs (byte-identical across two runs with `PYTHONHASHSEED=1`
under `-I` and `PYTHONHASHSEED=987` without; SHA-256):

| File | Rows | SHA-256 |
| --- | ---: | --- |
| node-94-115-drift.tsv | 233,324 | `2d6a10f473954ee0ca576b224bd9680847bd3bc116efcd6ef63bfb947dd782d8` |
| node-94-115-drift.json | — | `3e5cc0de28677b03cd3cd890fa694c1acb89f324e5a88f79885a114895b059a8` |
| node-94-115-paths.json | 63 | `2510fca9ee11e3174fec9407377de8f1ad8e3a7254b96623d3e43a49e6441f9b` |

The 14 MB TSV stays in ignored `work/`. The summary and path results are
retained here, and `validation.json` pins all three hashes plus every count
below.

| Observation | #94 | #115 |
| --- | ---: | ---: |
| `.text` FDE extents (= RE-001 FDE records) | 121,299 | 135,313 |
| Instructions decoded inside extents | 15,730,149 | 18,827,581 |
| `identical` rows / bytes | 2,016 / 396,679 | 2,016 / 396,679 |
| `moved_only` rows / bytes | 14,608 / 8,039,647 | 14,608 / 8,039,647 |
| `changed` rows (inferred pairs) / bytes | 1,606 / 1,861,740 | 1,606 / 1,882,017 |
| `duplicate_ordered` rows / bytes | 5,058 / 637,831 | 5,058 / 637,831 |
| `equivalent_unpaired` rows / bytes | 41,386 / 5,916,192 | 44,306 / 6,785,593 |
| `unmatched` rows / bytes | 56,625 / 52,545,326 | 67,719 / 64,919,650 |

- **Byte-equal code is small:** 16,624 functions (8.44 MB, 12.2% of #94's
  69.40 MB of FDE-covered code) pair uniquely with equal masked text; only
  2,016 of them are byte-identical. Most surviving code moved and only its
  address operands differ. Another 5,058 (0.64 MB) pair by duplicate order.
- **Duplicates dominate the remainder:** 85,692 rows have a masked twin across
  releases but no pairing of their own (generic instantiations and small
  thunks), so they are counted, not paired.
- **Catalogue paths agree with the binaries:** a path matches only as
  `<crate>/src/<file>` at a path boundary (#94 embeds absolute
  `/home/ubuntu/hl/code_Mainnet/…` paths, #115 relative ones). All 28
  `absent115` paths occur in #94 and not #115; all 35 `added115` paths occur
  in #115 and not #94 (`node-94-115-paths.json`). A bare suffix match would
  have hit std's `/src/time.rs`; the boundary test is a unit-tested negative
  control.
- **Independent cross-check:** `crosscheck.py` takes every 97th
  `identical`, `moved_only`, `changed` and `duplicate_ordered` row
  (21 / 151 / 17 / 53). It slices
  bytes using `readelf -S` offsets rather than the tool, and disassembles
  each function separately with `objdump --start-address/--stop-address`.
  Every sampled `identical` row has equal bytes; every `moved_only` row has
  differing bytes, equal size and equal disassembly once every hex number is
  masked (a wider mask than the tool's); every `changed` row has differing
  bytes; every `duplicate_ordered` row has equal size, equal masked
  disassembly and byte equality exactly as its `raw_equal` column says.
  0 contradictions.

## Reconciliation with an independent classifier

A separate classifier written without this tool's code
(`classification.csv`, SHA-256
`27b7e51c819aa7a5b3bfde6a48ebbe0df31952849906193e02f53d9d5303f40f`, not in
the repo) takes ranges from `readelf -wf`, digests from
`objdump --insn-width=16`, and pairs raw groups, then norm groups (zipped by
address order), then shape groups (size and mnemonic sequence → `changed`),
then positional pairs between anchors (→ `changed_positional`).
`reconcile.py` joins it to our TSV on the #94 start: all 121,299 #94 rows
join, with none missing on either side. Every cell is retained in
`reconciliation.json`. "Their norm equal" counts our pairs that the other
classifier's own digest also calls equal.

| Ours → theirs | Rows | Same partner | Their norm equal on our pair | Why |
| --- | ---: | ---: | ---: | --- |
| identical → moved | 2,015 | 2,004 | 2,014 | agree; theirs needs the same address for `identical` (0 by construction) |
| moved_only → moved | 14,133 | 12,026 | 14,133 | agree; 2,107 other partners are duplicate assignment |
| duplicate_ordered → moved | 4,937 | 3,688 | 4,937 | agree on equality; partner choice among duplicates differs |
| changed → changed / changed_positional | 196 / 5 | 184 / 5 | 0 | agree; 12 partner conflicts, below |
| equivalent_unpaired → moved / removed / changed | 32,039 / 7,476 / 1,871 | — | — | definition: we do not pair duplicates outside one anchor gap; they zip by address order |
| moved_only / identical / duplicate_ordered → removed | 344 / 1 / 92 | — | 343 / 1 / 92 | duplicate assignment: their address-order zip gave our partner to another group member |
| moved_only / duplicate_ordered → changed | 131 / 29 | 72 / 1 | 49 / 28 | 77 duplicate assignment; 83 their masking (below) |
| changed → removed | 1,405 | — | 0 | matcher strength: our call-graph inference; their shape rule needs equal size and mnemonics |
| unmatched_94 → changed / changed_positional | 3,170 / 15 | — | — | matcher strength: their shape rule pairs bodies we leave unpaired |
| unmatched_94 → removed | 53,440 | — | — | agree |

What the reconciliation found and fixed here:

- **Our immediate masking was wrong.** Masking immediates inside the mapped
  image (from `0x2e0`) hid real constants, and because the #94 and #115 image
  ranges differ, one constant could be masked on one side only. Before the fix
  this produced 142 `unmatched_94 → moved` and 66 `moved_only → changed` rows
  (for example `sub $0x348,%rsp` vs `sub $0x3d8,%rsp` at
  `0x1400d30 → 0x155fa10`). Immediates are now compared verbatim behind the
  PIE/no-TEXTREL guard; a mutation control with in-range constants and a unit
  test cover it.
- **Call-position pairing could claim a duplicate.** 72 `changed → moved`
  rows were call-position pairs whose #94 side had a masked-equal twin in
  #115. Call-position pairing now skips any body with a masked twin; the cell
  is 0.
- **A copy of an already-paired body was called unmatched.** 187 rows were
  `unmatched_94` although their masked body exists in #115, paired to another
  #94 copy. They are now `equivalent_unpaired`; `unmatched_94 → moved` is 0.

What remains, explained but not changed:

- **Their masking is asymmetric (83 + 1 + 1 rows).** The other classifier
  masks immediates ≥ `0x10000` inside each binary's own LOAD span (#94 to
  `0x59b0e80`, #115 to `0x6728924`). A constant between the two ends, such as
  `0x5f5e100` (100,000,000) or `0x5f5e0ff`, is masked in #115 only. For all
  85 of our masked-equal pairs that their digest calls different, recomputing
  their digest with the #94 span on both sides makes them equal; none is
  unexplained. That classifier's directory was not modified.
- **12 `changed → changed` rows have different inferred partners.** We pair
  by call position; they pair the same-size, same-mnemonic body by address
  order. Both sides label these as inferences, and neither result is an
  observation. 5 of our partners differ in size from the #94 function (for
  example 602 → 355 bytes), so their partner may be the better guess. For one
  row (`0x3c97270`) their partner is already our `moved_only` partner of
  another #94 function.
- **Matcher strength.** 1,405 `changed → removed` rows are our inferences that
  their shape rule cannot make, and 3,185 `unmatched_94 → changed*` rows are
  theirs that ours does not make. Neither is an observation.

## Implementation and comparison

No Rust implementation; deterministic offline tooling and static observation.

- `mutation_controls.py` assembles a C→A→B call chain, decodes the real
  bytes with its own pure-Python AT&T decoder (no objdump or readelf; the
  GNU tools are only an optional cross-check in `crosscheck.py` and
  `verify.py`, which skip with a reason on non-GNU) and mutates the #115 side. The checks are: moving B
  gives `moved_only` for A; changing an instruction, a constant (including
  one inside the code's address range on both sides), or a call
  target (to non-FDE code or to the PLT) gives `changed`; an added function
  gives `unmatched_115`; no mutation gives all `identical`.
- `tests/test_release_drift.py` adds negative controls: immediates and stack
  offsets are never masked, even inside the image range; duplicate masked
  hashes never get a hash-match class, and duplicates split across anchor gaps
  or with unequal counts stay unpaired; call position never claims a body with
  a masked twin; non-PIE or text-relocated inputs fail closed; the 2× size bound rejects a 201-byte partner of a 100-byte function;
  a path only behind a non-boundary byte does not match; an empty extent
  fails closed; output bytes are independent of input order and of
  `PYTHONHASHSEED` (0, 1, 4242).
- Nine deliberate tool mutations each fail the unit tests: masking every
  immediate, merging branch-target kinds, dropping call-position pairing,
  dropping the twin guard, dropping the per-gap count check, ignoring text
  relocations, dropping intra-extent branch offsets, not masking RIP
  displacements, and counting twins among unpaired rows only. The first three
  also fail `mutation_controls.py`.
- `verify.py` rebuilds into a temporary directory and checks the three output
  hashes, the retained files, 11 pinned summary values, the cross-check result
  and the mutation controls. It uses no `assert` and passes under `-I -B`
  and `-O -B`.

## Results and limitations

What this does not claim:

- **Not behavioural equivalence.** `moved_only` compares instruction text
  with addresses masked. Data behind a RIP-relative or image address is not
  compared, so a changed `.rodata` constant can still be `moved_only`.
- **`duplicate_ordered` pairs are inferred.** The bodies are equal after
  masking; which copy pairs with which is a guess by address order.
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

Next question: for the 1,606 inferred `changed` pairs, which differ only in
`.rodata`-referenced data or inlining? Which of the 56,625 unmatched #94
functions sit under the 28 `absent115` source paths?
