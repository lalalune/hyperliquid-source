# staking: reward-stage row ordering and bulk tree in node #94

This packet establishes how the previously stubbed reward-stage result rows are ordered and assembled into a tree for the tested inputs, enabling a reconstruction to preserve the observable order, optional-value records, duplicate handling, and tree shape.

- Component ID: `staking`, reward distribution and stage-result construction.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only and no source from it is included.
- Claim status: byte and relocation observations and bounded interpreter results below; field names and the reward-stage connection are inferences tied to the earlier packet; uncovered cases remain unresolved.
- Scope included and excluded: the seven selected sort and bulk-builder FDE ranges in `functions.tsv`, with contextual producer and host instruction anchors. The prior `staking-reward-tick-94` packet models sort and bulk construction as stubs. Reward amount calculation, reserve changes, the complete producer and host, the returned-map consumer, the real allocator and all other node code are excluded.

## Reproduce

From the repository root:

```sh
python3 tools/staking_reward_tree94.py --out research/work-items/staking-reward-tree-94
python3 -m unittest tests.test_staking_reward_tree94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/staking-reward-tree-94 && sha256sum -c MANIFEST.sha256)
```

For the independent-output comparison, set `TMPDIR` to a writable directory
and run:

```sh
REWARD_PYTHON="$(command -v python3)"
PATH='' PYTHONHASHSEED=1 TZ=UTC "$REWARD_PYTHON" tools/staking_reward_tree94.py --out "$TMPDIR/reward-tree-a"
PATH='' PYTHONHASHSEED=78219 TZ=Pacific/Honolulu "$REWARD_PYTHON" tools/staking_reward_tree94.py --out "$TMPDIR/reward-tree-b"
diff -r "$TMPDIR/reward-tree-a" "$TMPDIR/reward-tree-b"
```

The two output directories must initially be empty. The comparison returned no
differences. Python 3.12.3 on Linux x86-64 was used; GNU objdump 2.42 was used
only to inspect human-readable instructions. The generator and tests do not
call external programs or parse their output, and also passed with binutils
absent from `PATH`. The generator verifies the complete input SHA-256 before
analysis, uses the repository's `elf_index.py` and `fde_extents.py`, excludes
NOBITS from file mappings, and deterministically writes the eleven evidence
files. `MANIFEST.sha256` binds those files and this README. The local x86
interpreter and decoder are adapted from the repository's MIT-licensed
`tools/staking_reward_tick.py`; no captured binary is executed.

## Evidence

All addresses below are linked ELF virtual addresses. File offsets and
unwind-record addresses are in `functions.tsv`; their decoded FDE extents are
analysis windows, not a claim that unwind data enumerates all functions.
`instructions.tsv` contains the linearly decoded bytes and operations within
the seven windows. `branches.tsv` gives each conditional target, fallthrough,
and which directions occurred in the fixtures. Selected caller and producer
bytes are in `anchors.tsv`; indirect slots and dynamic memory symbols are in
`relocations.tsv`.

### Observed path and layout

| Step | Byte-backed observation |
| --- | --- |
| Producer row | At `0x3be56f6` the index is multiplied by 40. The writes at `0x3be5707`, `0x3be5712`, `0x3be5718`, and `0x3be571d` place the key, tag, and value in that row. |
| Empty and singleton | The host tests zero at `0x337372d` and tests one at `0x337373e`; the selected path skips sorting for those sizes. These host instructions are pinned, not executed by the fixture. |
| Small sort | For 2 through 20 rows, the host selects `0x33879d0`. It compares 20 bytes through the `memcmp` import; the observed order is ascending and equal keys retain input order. |
| Larger sort | At 21 rows the host selects slot `0x5775cb0`, whose RELATIVE relocation targets `0x3bc1610`; that entry reaches `0x3865c20`, `0x38879e0`, `0x33903c0`, and `0x3862e60`. The comparison result's sign, not its magnitude, determined the tested outcomes. |
| Scratch space | For tested lengths up to 4,096, the long sort uses stack scratch through 102 rows and allocates from 103. In the all-equal controls, 102 uses no sort allocation and 103 requests 4,120 bytes. The immediate `0x30d40` and other untested large-length branches are retained in the records. |
| Bulk builder | The host's direct call at `0x33737d6` reaches `0x2fbe050`. This walks adjacent equal keys, retaining the last two-word value, then builds an ordered address-keyed tree. A tag-0 record is retained as an entry, not omitted. |

The test input row is 40 bytes: key at `+0..+0x13`, four padding bytes at
`+0x14`, and two 64-bit words at `+0x18` and `+0x20`. Fixtures place a serial
in the padding solely to check sort stability; the tree's observed key and
value fields exclude it. A tag-0 payload is retained as raw bits in the
fixtures; its semantic value must not be assumed meaningful. `witnesses.tsv`
shows input, sorted and tree rows, including both duplicate orders and a
comparison where the deciding byte is near the end of the key.

The tree inspection checks key order, the recorded count, node occupancy and
all child-to-parent pointers and slots. In unique-key fixtures, 11 rows have
one leaf, while 12 yield a root and two leaves with 6 and 5 keys. At 1,727
and 1,728 rows the observed root heights are 2 and 3 respectively. These are
fixture observations, not an assertion about every possible allocation or
pre-existing tree. `topology.tsv` records selected trees, including the full
1,728-row topology. The builder is entered with an empty root matching the
selected host path; nonempty input trees are not covered.

### Inferences

The previous reward-tick work connects the producer to staging and interprets
its row as a validator and an optional amount. This packet binds the row
stores and the sort/build path, but does not rerun that producer or independently
prove those names. The tree here is the stage-result map, not the separate
state map of staged reward balances. No evidence here establishes that a valid
producer emits duplicate keys: duplicate fixtures test the builder's behavior
on adversarial inputs and the sort's preservation of equal-key order.

### Failure and corruption controls

`negative-controls.tsv` records 16 controls: 13 expected rejections and three
invariance checks. They include an incorrect digest, out-of-section and
out-of-FDE addresses, damaged selector bytes, a damaged sort relocation,
failed sort and builder allocation hooks, and flipped sort and duplicate
branches. Independently changing the synthetic allocation fill among three
bytes and the nonzero `memcmp` return magnitude among three values did not
change the tested results or topology. The sort fixture supplies a nonzero
synthetic context pointer like the host; on one 103-row case, replacing it
with zero also preserved the tested result and topology. This comparison
does not establish context independence for all inputs.

An invalid tag is rejected by the fixture constructor, and an unsorted bulk
input is rejected by the post-run tree checker; neither is presented as a
node-level input error. Allocation-failure hooks mark arrival at a target
failure sink, not the behavior of a real allocator or an observed node panic.
The root allocation in the host is outside the exercised range.

## Implementation and comparison

Not yet implemented in Rust; no source build or binary identity comparison is
claimed. The fixture interpreter runs the seven original instruction windows
with checked stand-ins for `memcmp`, `memcpy`, `memmove`, allocation, free and
failure sinks. Its separate Python model sorts by the 20-byte key and folds
equal-key runs; it does not share the machine's tree-building code. The model
is compared with the raw sorted rows, tree contents and structural checks.
Allocation and free calls are recorded by the harness; free is not a real
deallocation and does not check allocator ownership or use-after-free behavior.

The 326 deterministic cases include all 152 permutations of 2 through 5
distinct keys, 30 permutations of a repeated-key multiset, alternating and
organ-pipe orders, mixed keys, and sizes through 4,096. They produced zero
model mismatches. At least 1,763 of 1,998 decoded instruction sites were
reached; 126 of 136 conditional sites were reached, with both outcomes at 78.
These figures are for the selected windows and fixtures, not node coverage.

`mutations.tsv` flips every reached conditional opcode and tries selected
fixtures, with a bounded additional stress case for survivors. Of 126 edits,
21 changed a compared result, 80 stopped in the interpreter or a hooked
failure sink, and 25 survived the selected cases. Stops are not counted as
behavioral differences or proof of a target failure; survivors are not
classified as benign. The unmodified cases pass before mutation.

## Results and limitations

35 targeted unit tests passed with no skips. Two generated outputs matched
byte for byte under different hash seeds and time zones. No full repository
test suite was run. No completion gate is requested and no component progress
is advanced.

Unresolved: the ten unreached conditional sites, outcomes not taken at other
sites, unusual or malformed iterator state, pre-existing builder roots,
lengths above 4,096, actual allocation/unwind behavior, and whether all valid
stage inputs preserve uniqueness and stable order. The evidence does not
establish sorting correctness for every possible input or reproduce the
complete tick, allocator, Rust build, or whole ELF.

Next question: trace the consumer of the returned stage-result tree and check
whether tag-0 and tag-1 zero-valued entries have distinct reporting or
accounting effects.
