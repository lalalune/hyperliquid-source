# staking: reward-stage and compound-map insertion in node #94

This packet recovers how the previously opaque staged-reward and compounded-payout map insertions split nodes and return value slots, so a reconstruction can preserve both layouts and the resulting tree structure across the reward path.

- Component ID: `staking`, reward distribution and compounding.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is not used as implementation.
- Claim status: FDE, ELF bytes and relocation observations; bounded instruction interpretation and an independent tree model for the stated synthetic fixtures; application names and their connection to reward arithmetic use earlier evidence and are inferences here.
- Scope included and excluded: the two FDE-described insertion ranges in `functions.tsv`; selected existing caller and reward-path instruction sites in `anchors.tsv` and `pipeline-calls.tsv` supply context only. Earlier work owns those callers and the reward arithmetic. Search for a slot, old-value replacement, the actual allocator, rollback, unwinding, networking and execution of the captured binary are outside scope.

## Reproduce

Run from the repository root with Python 3.12.3 on Linux x86-64, using the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The generator authenticates the full input digest before parsing; it calls no external program and does not start the captured executable. It deterministically writes all TSV and JSON files in this directory:

```sh
python3 tools/staking_reward_map_insert94.py --out research/work-items/staking-reward-map-insert-94
python3 -m unittest tests.test_staking_reward_map_insert94
(cd research/work-items/staking-reward-map-insert-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For two fresh comparison directories, with a writable `TMPDIR` already set:

```sh
REWARD_PYTHON="$(command -v python3)"
PATH='' PYTHONHASHSEED=1 TZ=UTC "$REWARD_PYTHON" tools/staking_reward_map_insert94.py --out "$TMPDIR/rewardmap-a"
PATH='' PYTHONHASHSEED=97823 TZ=Pacific/Honolulu "$REWARD_PYTHON" tools/staking_reward_map_insert94.py --out "$TMPDIR/rewardmap-b"
diff -r "$TMPDIR/rewardmap-a" "$TMPDIR/rewardmap-b"
```

Input and body hashes, exclusive FDE bounds, FDE/CIE/LSDA coordinates, file offsets and decoded row counts are in `functions.tsv`; `MANIFEST.sha256` binds the packet files. `instructions.tsv` is a linear decode of each selected FDE, including bytes not reached in the fixtures. It is not a claim that all those rows are executable instruction boundaries. GNU objdump 2.42 was used for human inspection only and is not invoked by the generator or tests. The optional inspection commands were:

```sh
objdump -d --start-address=0x2f3f5d0 --stop-address=0x2f40166 artifacts/node/94/hl-node
objdump -d --start-address=0x2f46550 --stop-address=0x2f47169 artifacts/node/94/hl-node
```

## Evidence

All code coordinates below are ELF virtual addresses, not rebased runtime addresses. The common `.eh_frame` parser supplies exclusive FDE extents; direct calls to their starts corroborate entry points. FDE extents alone do not establish a complete function census or all CFG boundaries. `pipeline-calls.tsv` decodes the selected direct calls from the reward tick to the stage producer and from the payout to the compound sink. `incoming-calls.tsv` binds the two insertion entries; only the selected site bytes of already researched callers are included.

| Selected role | FDE extent | Key bytes | Value bytes | Node parent / value / key offsets | count / child-edge / children offsets | leaf / internal allocation |
| --- | --- | ---: | ---: | --- | --- | --- |
| staged map | `0x2f3f5d0..0x2f40166` | 20 | 8 | `0x0 / 0x8 / 0x60` | `0x13e / 0x13c / 0x140` | `0x140 / 0x1a0` |
| compound map | `0x2f46550..0x2f47169` | 21 | 8 | `0x0 / 0x8 / 0x64` | `0x62 / 0x60 / 0x150` | `0x150 / 0x1b0` |

The caller sites put zero in the value argument on the insertion path. The two entry adapters increment the map-length word after the helper returns and produce the address `node + 8 + 8 * slot`; the selected context bytes also show distinct existing-entry branches bypassing insertion and the length increment. The helper itself leaves the length word unchanged in the tested fixtures. The contexts include selected checked-add instructions after the returned slot is obtained; this packet does not execute or independently establish their overflow policy.

For a full node holding 11 keys, the observed split choice is:

| Incoming gap | Promoted old slot | Left keys after insertion | Right keys after insertion |
| --- | ---: | ---: | ---: |
| 0 through 4 | 4 | 5 | 6 |
| 5 | 5 | 6 | 5 |
| 6 | 5 | 5 | 6 |
| 7 through 11 | 6 | 6 | 5 |

With space, the helper shifts the appropriate key and value tails and returns a cursor identifying the inserted pair. On a full leaf, it allocates a right leaf. Promotion into a nonfull parent stops the cascade; a full parent splits and can propagate upward. A full root allocates a new internal root. The independent model checks all tree keys and values, the exact shape, parent pointers, child indices, allocation order, preserved map-length word and returned cursor. `cases.tsv` records the individual fixtures and tree hashes; `branches.tsv` records each decoded conditional and the observed outcomes. `transfers.tsv` records all direct conditional and unconditional jumps in the two windows; the generator requires each target to coincide with a linearly decoded row, a consistency check rather than independent proof of reachability.

`controls.tsv` identifies separate failed leaf, internal and root allocations, missing-root, invalid-count and invalid-height fixtures. Each stops at a recorded external failure call in the interpreter. The two allocation sizes and failure-site addresses differ between map layouts. This says where these fixtures arrive, not what the real external handlers do or whether any partially changed state is rolled back. Four single-byte mutations per helper attack capacity, split threshold, key tail and branch condition. An additional out-of-range jump per helper is rejected by the selected-FDE guard. `relocations.tsv` records the allocator and failure slots and identifies the `memcpy` and `memmove` imports directly from ELF relocation and dynamic-symbol bytes. The interpreter distinguishes them and rejects overlapping `memcpy`.

**Inferences:** `staking-reward-tick-94` identifies the first map with validator staged rewards, and `staking-stake-accounting-94` identifies the second map as `(user, reward kind) -> amount`. Those studies also connect stage, payout and compounding; the present context call sites do not prove all gating or dataflow between them. The byte interpreter here receives an already located insertion cursor. It does not compare keys to find that cursor, and the synthetic fixture ordering is an input, not recovered comparator behavior. Synthetic cases include a kind-0 key followed by the same 20-byte address with kind 1; both values and keys survive the selected insertion and splits. The already located cursor is fixture-supplied, so this does not prove the search will find those positions or that every combination is reachable in chain state.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Rust build, helper closure, relocation and whole-ELF equivalence: **not yet implemented/measured**. The generator's evaluator interprets the two selected code windows over synthetic memory; a separately written tree model predicts the resulting pair sequence, tree shape, cursor and allocations. Allocation, copies and failure sinks are checked hooks. It does not execute the node or measure an independently compiled Rust body. No operand normalization or binary-equivalence percentage is claimed.

## Results and limitations

- 1,992 normal synthetic cases agree with the separate model, including all leaf gaps, parent split gaps, cascades through three ancestors, zero and maximum values, and both compound-key kind bytes.
- 28 fault and mutation controls produced their expected result. The focused unittest suite passed 26 tests with zero skips. The exact decoded and reached instruction counts are 601/644 for staged and 639/684 for compound. Both outcomes were observed for 30/38 and 30/40 decoded conditional sites respectively; failure fixtures contribute to those numbers. They are fixture coverage, not a whole-component denominator.
- The allocator, actual memory routines, external failure handlers, search/duplicate detection and cleanup or rollback are not evaluated; malformed cursors and the remaining branch outcomes are unresolved. The interpreter is a bounded model and is not native execution. Copies reached through different paths and other binary releases are not covered.
- No progress gate is requested. Next question: independently reconstruct and validate the search and occupied-entry adapters, including duplicate detection and overflow/error behavior, against target-grounded cases.
