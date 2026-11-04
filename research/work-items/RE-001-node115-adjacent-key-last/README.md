# RE-001: node #115 adjacent-key compaction keeps the last record

Component: consensus-associated collection transformation; RE-001 function bind,
preparatory evidence for RE-008. Base/reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All coordinates are original ELF virtual addresses unless explicitly file offsets.
New analysis, models, tests and documentation are independently authored under MIT.

## Bounded question and answer

Does this leaf keep the first or last complete record of each adjacent equal-key run, and which bytes form the key?

**Rule.** Given an object in RDI with backing pointer at `+0x8`
and unsigned length at `+0x10`, the leaf compacts
maximal adjacent runs with equal leading **20 bytes** of each
**32-byte record**. It keeps the **last complete record** of each
run, including its trailing 12 bytes, in original run order,
and stores the run count at the length field. Nonadjacent equal keys remain
separate. Short inputs and inputs without adjacent equality receive no writes.
On compaction, the backing tail can change and is not erased. The observed result
is memory and length; an original source-level return type is not recovered.

This rule assumes a valid stack/return and readable length field. For the
nontrivial route, the pointer field must be readable and the backing range must
be writable, nonwrapping, cover the original length times record size, and be
disjoint from the object. No concurrent mutation is allowed. Arbitrary invalid
pointer/length combinations are outside the theorem.

## Boundaries and instruction evidence

The complete window is `0x5b2d510..0x5b2d648` (half-open), file offset
`0x5b2c510`, body SHA-256 `b0da65b42a0b5f1bea941c34249f63d6cfea9f27fb6ac0cf4e6c81290af3fbe4`.
Actual FDE `0xfd1f08` (file offset `0xfd1f08`)
references CIE `0xca6ed8` (file offset `0xca6ed8`),
augmentation `zR`, with no LSDA. `records.json` retains complete FDE/CIE bytes,
body bytes, strict decoded operands and CFG edges. `instructions.txt` is the
complete byte walk, including internal NOP padding. Every conditional target is
an instruction boundary inside the body; every non-padding instruction is
reachable in the structural CFG. Terminal RETs and the following INT3 fill through
`0x5b2d650` corroborate the FDE extent. This establishes
this bounded leaf, not a general rule equating FDEs with source functions.

All reported packet counts below are derived from `records.json.metrics` and
checked against this README by the targeted tests.

| Metric | Count |
| --- | ---: |
| body_bytes | 312 |
| branch_sites | 8 |
| callees | 0 |
| caller_functions | 1 |
| caller_sites | 1 |
| e8_sites | 1 |
| e9_sites | 0 |
| external_padding_bytes | 8 |
| instructions | 74 |
| internal_padding_bytes | 19 |
| ret_sites | 2 |
| vectors | 40 |

The leaf has no calls, indirect transfers, RIP-relative data accesses or external
branches, so its callee identity/extent set is empty. No callee behavior is left
conditional. Internal alignment bytes are inside the body hash; external INT3
padding is recorded separately and earns no implementation-byte credit.

## Why the key comparison and last-record rule follow from bytes

- `0x5b2d510..0x5b2d52f` loads the length, uses unsigned JB to return for short
  inputs, loads the backing pointer, computes the last comparison offset by
  shift and subtraction, and initializes the scan. The admitted memory geometry
  makes these address calculations exact, without integer wrap.
- `0x5b2d540..0x5b2d56f` compares adjacent leading SIMD blocks. MOVD loads the
  remaining key fragment and zeroes its upper lanes. PCMPEQB therefore produces
  all-one upper lanes for that fragment; PAND combines the leading-block equality
  and fragment equality. PMOVMSKB followed by comparison with
  `0xffff` is true exactly when the whole key matches.
  The machine-readable `mask_lane_key_dependencies` shows which key bytes
  contribute to each mask bit. Payload bytes are not compared.
- `0x5b2d571..0x5b2d57d` advances by the decoded record stride until an equal pair
  is found or the end is reached. Without an equal pair it returns without writes.
- `0x5b2d57e..0x5b2d5ad` loads and swaps both halves of the first equal pair.
  The later row now occupies the retained position. RDX becomes the write index
  after the retained prefix; RAX is the remaining unread count. JBE handles an
  equal pair at the end. The count cannot underflow under the stated geometry.
- `0x5b2d5dc..0x5b2d616` compares the next unread row with the last retained row,
  using the same key relation. On inequality, `0x5b2d5c0..0x5b2d5da` copies the
  complete row into the write position and increments the write index. On equality,
  `0x5b2d618..0x5b2d641` swaps the complete unread row with the last retained row,
  leaving the write index unchanged. Both routes advance the read pointer and
  decrease the remaining count.
- `0x5b2d643` stores the write index as the new length, then returns.

Inductive invariant: before processing an unread row, the prefix up to the write
index is the last complete representative of every run in the processed input.
The last retained key either equals the next input key, replacing its representative,
or differs, extending the prefix. Reads never revisit the already-processed tail,
and writes never reach a future unread row. The invariant proves the stated rule
for every valid finite input, including a run extending to the last row. It does
not require sorted input and does not prove global deduplication. Copying after a
duplicate can leave repeated stale rows in the backing tail; only the live prefix
has the compacted interpretation.

## Direct caller and source association

The census scans every eligible byte position in `.text`
`0x1419300..0x63f0a00` (83719936 bytes) for E8/E9 rel32
whose signed displacement targets the leaf. The sole hit is CALL at
`0x4dff15a`, in actual FDE `0x4dfe6d0..0x4dff979`.
It is corroborated by the decoded LEA of `[rsp+0x200]` into RDI followed by the
CALL and reloads of the object fields, plus incoming direct jumps to that LEA.
All these relied-on instructions are decoded by the same strict Python decoder.
The census counts byte-pattern matches; it does not decode the entire text section,
prove all caller reachability, or discover indirect calls/data-held pointers.

The caller FDE also contains a RIP-relative LEA at `0x4dfe87d` naming
Location-shaped record `0x649ccf8`. Its pointer is resolved by the retained
`R_X86_64_RELATIVE` relocation to `0x44f5d5`. Length, raw path bytes and
line/column bind it to `node/src/consensus/execution_state.rs:138:29`.
This is observed first-party source association through a direct caller, not a
recovered name, proof of exclusive ownership, or interpretation of key/payload
fields as particular consensus entities. The caller itself is not behavior-bound;
its other helpers and source-level collection type remain unresolved.

## Novelty and scope

Before creating this packet, at the base commit above, these exact searches
returned **empty stdout and exit status 1**:

```sh
rg -i '5b2d510' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '95606032' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -in 'adjacent-key-last|adjacent_key_last|run-key-compact|run_key_compact|5b2d510|95606032' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

These are historical pre-creation checks: this packet necessarily matches them
now. The callee novelty check is vacuous because the bound leaf has no callees.
Its start is within the assigned band and outside the excluded crowded interval.
Only this new packet, its generator and targeted tests are added. No imported
records, catalogue, progress gate, existing tool/test or upstream pin is changed.

## Reproduction and controls

From the repository root with the authenticated artifact present:

```sh
python3 tools/node115_adjacent_key_last.py --out research/work-items/RE-001-node115-adjacent-key-last/
python3 -m unittest tests.test_node115_adjacent_key_last -v
python3 research/work-items/RE-001-node115-adjacent-key-last/verify.py
make verify
make catalogue-check
```

The generator authenticates the entire artifact before interpretation or output
creation, uses a single read-only mmap, and writes deterministic JSON, byte walk,
README, verifier and manifest. It requires Python 3.10+ and only stdlib plus the
repository's existing stdlib ELF/FDE parsers. The local validation environment
was Linux x86-64 with Python 3.13.5. GNU objdump 2.44 was used for exploratory
cross-checking; generation, tests and verification never invoke or depend on it.
No captured node/visor, emulator, service, network request or installation is used.

`compact_model` is an independently authored grouping specification;
`byte_walk_model` expresses the decoded copy/swap schedule, including the tail.
The retained vectors cover empty/singleton/distinct runs, last-payload retention,
end-of-input duplicates, separated repeats, and a change at every byte position.
Tests additionally exhaust short key sequences and compare the SIMD-lane relation
with byte equality. These are instruction-grounded static fixtures, not outputs
captured by running the target. Corruption controls cover wrong/truncated input,
every body byte, unsupported/truncated instructions, an altered key load, flipped
branch, shifted FDE, caller target, source relocation and external padding.
Manifest checks enforce an exact path whitelist and regeneration, not merely
hashes of whatever files an altered manifest names.

## Results, non-claims and next step

Before this packet, the selected address had no bind in the checked research or
PR lists. The result closes the complete local transformation and its key width,
keeper choice and mutation schedule. The full branch walk and induction are the
semantic argument; a successful generator run alone is not equivalence evidence.

No Rust implementation or build comparison is provided. Source/compiler/dependency
closure, original ABI/types, caller sorting/admission, protocol meaning, runtime
fault/unwind behavior on invalid inputs, indirect consumers and whole-ELF identity
remain unmeasured. There are no normalization masks or transplanted implementation
bytes. All component/full-scope acceptance gates remain open; no progress update,
hosted CI result or full repository test-suite pass is claimed.

Next: recover the caller's input construction and ordering before assigning
consensus meaning or global uniqueness to the compacted records.
