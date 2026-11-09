# RE-008: reconstruct node #115 consensus quorum 0x595bc40 and the stake quorum behind it, from bytes

This packet lets the Rust reconstruction write the whole quorum decision of node #115 as one rule: a strict two-thirds stake test with saturating u64 sums (`3 * signed > 2 * total` on 128 bits, 0x4d3e1a0), followed by a count test that compares the number of signers found in the validator set with `clamp(f, 0, 0.7) * validators` as doubles, where `f` is a config double (any non-finite value means 1.0, a stored zero skips the count test), with strict `>`, a u64 to f64 conversion that rounds once, and a stake map that may be a B-tree or a ring buffer. 12,568 cases from six function bodies run as real bytes agree with a separate rule list, and 222 of 222 negative controls are detected.

- Component ID: `consensus` (task RE-008)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; reference labels are leads only, nothing is copied
- Claim status: observation for every row that ran or is pinned by bytes; inference where a section says so (names such as stake map and validator set); unresolved items are listed under Results and limitations
- Scope included: `0x595bc40` (1,576 bytes, whole body), `0x4d3e1a0` (365), `0x4e44c00` (515), `0x4e406f0` (669), `0x5138730` (534), `0x57f54e0` (459) run for real, with memcmp (GOT `0x64dfb50`) and the panic GOT slots as recording stubs. In a second mode GOT slot `0x64e6a98` (the call to `0x4d3e1a0`) is replaced by a recording stub whose answer the case chooses, so the count stage is tested alone
- Scope excluded: the callers of `0x595bc40` (the quorum slot `0x64e8780` is only named in merged `RE-008-tc-parallel-abort-115` as one step of its list, without semantics; nothing here repeats that packet), the stake-set lookup `0x595e5c0`, the vote loop and signature check `0x57e8bd0` in `0x595f880`, the origin of the config double at `+0x88`

## Reproduce

Run from the repository root with Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed and nothing touches a network. The tool refuses any other digest. It writes every file in this folder except this README and `MANIFEST.sha256`, with `multiprocessing` workers; one run takes a few minutes.

```
python3 tools/re8_quorum_count115.py --out research/work-items/RE-008-quorum-count-fraction-115
python3 -m unittest tests.test_re8_quorum_count115
python3 tools/artifacts.py verify
(cd research/work-items/RE-008-quorum-count-fraction-115 && sha256sum -c MANIFEST.sha256)
```

Two output directories made with different `PYTHONHASHSEED` and `TZ` values were compared with `diff -r` and are byte-identical. Peak memory is 0.38 GB (measured 380,108 kB resident).

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`; function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

### Observations: the rule

`0x595bc40(config, stakes, signers)` returns one byte:

1. It calls the stake quorum through GOT slot `0x64e6a98` (RELATIVE addend `0x4d3e1a0`) with `(stakes, signers)`. A zero low byte returns false at once; nothing else is read. The upper bytes of the answer are ignored (`test %al,%al`).
2. It reads the double at `config+0x88`. If its absolute bit pattern is above `0x7fefffffffffffff` (infinity or NaN, any sign) the fraction is 1.0 (constant at `0x4592b0`). Otherwise it is `min(0.7, max(0.0, x))` with the SSE operand order of the bytes (constant at `0x459a10`); minus zero and every negative value give a clamped zero. A clamped zero returns true immediately, without looking at any signer.
3. It walks the signer set in key order (null root means no signers whatever the length word says). Each 20 byte key is searched in the validator set at `stakes+0x20` (root, height at `+0x28`, node scan with 20 byte memcmp: a positive result moves on, zero is a hit, negative descends). `signed` counts hits; a null validator root counts none.
4. It returns `float(signed) > fraction * float(total)` where `total` is the word at `stakes+0x30` (a stored count, not recomputed from the tree), converted from u64 with the two-halves trick (one rounding), and compared strictly. Exactly equal gives false.

`0x4d3e1a0(stakes, signers)` is the stake test: `signed` is the saturating u64 sum of the stake of every signer found in the stake map at `stakes+0` (`0x4e44c00`), `total` the saturating sum of every stake in the map (`0x4e406f0`), and the answer is `3 * signed > 2 * total` on 128 bits (`mul` by 3, doubled total with its carry bit, `cmp` and `sbb`, `setb`). Exactly two thirds fails. A stake map whose first word is `0x8000000000000000` is a B-tree (root at `+8`, height at `+0x10`, length at `+0x18`, stakes at node `+8`, 20 byte keys at node `+0x60`); any other first word is a ring of 32 byte elements (key, then the stake at `+0x18`) searched by `0x57f54e0`. Signers are produced by the set iterator `0x5138730`.

### Observations: layouts

`layouts.tsv` lists argument and node layouts with reading sites. Set node: parent at `+0`, keys at `+8`, parent index `+0xe4`, length `+0xe6`, edges `+0xe8`, no values; stake tree node: stakes `+8`, keys `+0x60`, parent index `+0x13c`, length `+0x13e`, edges `+0x140`. `fractions.tsv` lists the 40 tested double bit patterns with their class and effective value.

### How it was run

`path.tsv` lists 6 functions run as real bytes; `function-rows.tsv` has the 830 reached instruction rows with their raw bytes and `constants.tsv` their immediates. The body runs from its first byte under an x86-64 row evaluator in the tool over real B-tree set fixtures (heights 0 to 2, built by the node's own node layout and checked back through their parent, index and length words) and ring buffers with random heads. 12,568 cases (18,529,070 executed instructions):

- `fraction_grid/false`: 1227
- `fraction_grid/true`: 1101
- `precheck_value/false`: 244
- `precheck_value/true`: 76
- `random_trees/false`: 4598
- `random_trees/true`: 2602
- `signer_root_null/false`: 44
- `signer_root_null/true`: 16
- `stake_quorum_ring_boundary/false`: 417
- `stake_quorum_ring_boundary/true`: 33
- `stake_quorum_ring_small/false`: 295
- `stake_quorum_ring_small/true`: 5
- `stake_quorum_ring_wide/false`: 202
- `stake_quorum_ring_wide/true`: 248
- `stake_quorum_tree_boundary/false`: 423
- `stake_quorum_tree_boundary/true`: 27
- `stake_quorum_tree_small/false`: 288
- `stake_quorum_tree_small/true`: 12
- `stake_quorum_tree_wide/false`: 192
- `stake_quorum_tree_wide/true`: 258
- `stake_root_null/false`: 99
- `stake_root_null/true`: 21
- `u64_rounding/false`: 84
- `u64_rounding/true`: 56

`cases.tsv` is every fifth case (index, group, sizes, bit pattern, total, precheck word, result, steps, memcmp calls). `spec_run` in the tool is a separate rule list with no instruction rows: it predicts the result byte and, in stub mode, the exact ordered list of stub calls (the precheck call and every memcmp key pair of every signer search), so node scan order is compared as well as the answer. In real-precheck mode the stake-phase memcmp calls are not compared (only the count-stage ones are).

### Inferences, kept apart

- Calling the first map of the argument a stake map and the set at `+0x20` the validator set rests on how the bytes use them (values summed versus keys only); the names are not in the bytes.
- Reading `0.7` as a cap on a minimum participation fraction is inferred from the clamp; the bytes show only the clamp.
- Reading `stakes+0x30` as the number of validators is inferred; the body uses it only as the multiplier.

## Implementation and comparison

Rust implementation: not yet implemented. `spec_quorum` and `stake_quorum` in the tool are the comparison model. Original rows against the rule list: 12,568 of 12,568 equal on result and call log, first full run. Controls: 222 negative controls, 222 detected: byte edits (every conditional and every immediate of the reached rows of the six bodies; each runs on at most 64 of the cases that reach it, one outcome class at a time): 186 of 232 killed, 46 survivors listed in `mutations.tsv` and not claimed equivalent; deliberately wrong rule lists (16: precheck ignored, NaN as zero, no upper clamp, clamp at two thirds, non-finite as clamp, zero not special, all signers counted, wrapping sums, at-least two thirds, one half, count instead of stake, total from tree size, total truncated to 32 bits, total as f32, `>=`, signers and total swapped); layout fields moved by 8 bytes (5 node fields, 7 argument offsets); range controls (wrong digest, non-FDE start, address outside every FDE or section, step limit, fixture arena too small, rule list asked about another world, keys not equal to the tree contents). `controls.tsv` has every row with its first witness.

## Results and limitations

`evidence.json` and `measure.json` have the metrics. No progress gate is requested.

- The callers of `0x595bc40` are not read here; where the config double comes from (`+0x88`) and how `stakes+0x30` is kept equal to the validator count are unresolved.
- Stake map ring elements use a fixed padding byte; only the key and the stake at `+0x18` are read by the bodies.
- `0x5138730` runs only in the forms the signer fixtures take (heights 0 to 2); iterator back-state words are not exercised separately.
- `0x57f54e0` is run through ring fixtures only; its panic exits and the unwind pads of all six bodies are not run.
- 46 byte edits survive on the picked cases; a larger case set may kill some, none is claimed equivalent.
- No claim about network order, other nodes, or a real chain.

Next question: what does the QC verifier `0x595f880` do around this call (stake-set lookup `0x595e5c0`, digest builder `0x4e00160`, the vote loop with `0x57e8bd0`), and how does the wrapper `0x595fd20` map its results to the 0x2e, 5, 6 and 0x2d tags?
