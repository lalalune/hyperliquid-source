# RE-006: long trigger-candidate sort before order insertion on node #94

This packet resolves the previously stubbed long sort between trigger selection and firing: it identifies the two concrete sort chains, their scratch-buffer and run thresholds, and the tie choices in both merge directions, so a reconstruction can retain candidate order at those merge boundaries and reproduce the allocation decisions.

- Component ID: `orderbook` (task RE-006, trigger-to-insert transition).
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not source for the implementation or evidence for these claims.
- Claim status: observations below are linked-byte observations or explicitly described arithmetic derived from those bytes. Labels and product implications are inferences; unanswered questions are listed separately.
- Scope included and excluded: eight previously unpinned FDEs in the long-sort, run/merge, partition, small-sort and pivot chain. Two selector call sites and the previously studied short sorter and compactor are context only. Trigger selection, firing, the insert body, allocator internals, external calls and the third execution instance are excluded.

## Reproduce

From the repository root, with the authenticated node #94 file in its normal artifact location:

```sh
python3 tools/artifacts.py verify
python3 tools/trigger_long_sort94.py --out <tmp-dir>
diff -r <tmp-dir> research/work-items/RE-006-trigger-long-sort-94 --exclude README.md --exclude MANIFEST.sha256
python3 -m unittest tests.test_trigger_long_sort94
python3 tools/catalogue.py --check
```

The collector and tests use Python 3.12.3 and the standard library, importing the repository's `tools/elf_index.py` and `tools/fde_extents.py`. Input authentication precedes generation. They use no disassembler, external program, clock, locale-dependent ordering or network. They do not execute or emulate the node. `MANIFEST.sha256` covers this README and the eight generated files; from this work-item directory it can be checked with `sha256sum -c MANIFEST.sha256`.

The generated `evidence.json` carries the full input digest, FDEs, pair comparisons, constants, selected calls and branches; `windows.tsv` contains the exact byte windows, `calls.tsv` the direct and relocation-backed edges, `branches.tsv` the selected conditional targets, the two boundary tables the arithmetic cases, `small-network-model.tsv` a model of one pinned four-row network, and `small-sort-model.tsv` a bounded model of its surrounding small-sort path. Addresses are linked ELF virtual addresses (VA). File offsets are separately labelled; all selected code is file-backed `.text`, whose file offset is VA minus `0x1000`. Each selected start is checked against its `.eh_frame_hdr` entry and its decoded FDE. FDEs are unwind extents, not proven source-level function boundaries.

## Evidence

### Boundary and call path

The earlier `RE-006-trigger-order-fire-94` packet identified selection, firing, and insertion but stubbed the long sort. The two selector functions are outside this packet's subject. Here the selector's append window at `0x4321d86` and call windows independently link the record and entry to the unstudied sort. At the append the key is stored at row `+0x00`, 20 user bytes at `+0x08`, and a qword from the tree entry at `+0x20`; row spacing is `0x28`. The earlier packet identifies those as size, user and order ID respectively. The four bytes between the user and final qword are not assigned a meaning here.

| Stage | First chain | Second chain | Evidence |
| --- | --- | --- | --- |
| Previously studied selector, contextual only | `0x4321930` | `0x4320f80` | Its 0/1, 2..20 and 21+ decisions and incoming calls are pinned as selected sites. |
| Long-sort entry | `0x4486f50..0x4487057` | `0x44898b0..0x44899b7` | Selector's indirect slots resolve to these FDE starts through `R_X86_64_RELATIVE`. |
| Run detection and merge | `0x4dc43b0..0x4dc4a9b` | `0x4db8660..0x4db8d4b` | Direct calls from long-sort entries. |
| Partition and recursive fallback | `0x4496ec0..0x4497436` | `0x4491c40..0x44921b6` | Resolved indirect slots; each calls back to its run/merge entry on budget exhaustion. |
| Shared bounded sorter | `0x4919550..0x4919b36` | same | Direct call for a partition shorter than 33. |
| Shared pivot helper | `0x45c1360..0x45c1426` | same | Direct call at partition length 64 or above. |

On returning from the long sort, the first selector follows the same path as the short-sort arm and calls the previously studied `0x454cf20` compactor. This is an external edge, not a new claim about its body. The two selector call sites and the first selector's short-sort and compactor edges are recorded so the new chain can be placed on the transition path without reassigning those existing functions.

For the surrounding transition, the earlier trigger packet establishes the selected rows' meaning and the host's sequential firing logic. The `context_*` edges in `calls.tsv` independently pin that host-to-selection and firing-to-insert chain, without making the previously studied bodies new subjects here:

```text
first:  0x4cf37f0 -> 0x4321930 -> long-sort chain -> selector return
        host -> 0x4d44470 -> 0x42ff010 -> 0x4311140
        host can also call 0x42ff010 directly
second: 0x4cf94a0 -> 0x4320f80 -> long-sort chain -> selector return
        host -> 0x4d47070 -> 0x4300950 -> 0x4314da0
```

These static edges do not alone prove which branch is taken, or that a selected trigger reaches insertion. The prior packet's price gate and result branches remain applicable, and its selector, wrapper, firing and insert bodies remain excluded from this packet.

### Scratch-buffer and branch decisions

These entries compare the first qword of each 40-byte record as an unsigned value. The earlier selector analysis identifies the word as size. Its `0x4322206` branch sends counts at least 21 to the long entry, 2 through 20 to its earlier short sorter, and counts below 2 past sorting. For `n >= 21`, the long entry computes `half = n - floor(n / 2)` and `required = max(min(n, 200000), half)`:

| Input condition | Observed path |
| --- | --- |
| `21 <= n <= 102` | Uses stack scratch with capacity 102 records, or 4080 record bytes, within a 4096-byte stack reservation. |
| `n >= 103` and `half <= 0x333333333333333` | Requests `required * 40` bytes, passes the returned scratch and its record capacity to run/merge, then frees that allocation on normal return. |
| `half > 0x333333333333333` | Enters the capacity-error call before the allocation call; this is arithmetic at the helper boundary, not a claim that such a candidate vector can exist. |
| Allocation returns null | Branches to the allocation-error call before any run/merge call. |
| Run/merge unwinds after heap allocation | The cleanup arm frees the heap scratch before resuming unwinding. |

For counts through 200000, `required = n`; it remains 200000 for 200001 through 400000, then becomes `ceil(n / 2)`. The generated table includes both sides of each change and the raw arithmetic bound. These are static calculated cases, not observed node executions or an operational memory limit.

The wrapper passes a flag set for `n < 65`. The run/merge entry rejects a count below 2 by returning. For count below 4097 it computes `min(ceil(n / 2), 64)` as its run threshold. At 4097 or above, it obtains `k = ceil(floor(log2(n)) / 2)` and uses `(2^k + floor(n / 2^k)) / 2`, rounded down. `run-boundaries.tsv` gives adjacent arithmetic checks. This threshold controls the recorded run-processing branches; it is not asserted to be the final length of every run.

In the partition entry a subrange below 33 calls the shared small sorter. For 33 through 63 the selection is inline; at 64 or above it calls the shared recursive pivot helper. The small sorter first returns for fewer than 2 rows, then checks scratch capacity against `n + 16`; a too-short capacity reaches `ud2`. Its at-most-7 branch uses insertion-shaped moves, and `0x491985e` does not shift a row whose key equals the preceding key. Exhausting the partition budget branches back to run/merge. The exact sites and taken targets are in `branches.tsv`; this is a selected branch table, not a census of every branch in each extent.

### Runs, ties and merges

The run finder compares the first two keys. A second key below the first starts a descending run, which is extended only while each next key is strictly below the preceding key. Equality stops it before reversal. A nondecreasing run accepts equal adjacent keys. The reversal copies five qwords per record (`0x28` bytes), preserving the whole associated row.

When two runs can be merged, the core copies the shorter side to scratch. The two loops make complementary tie choices:

| Output direction | Comparison | Equal-key choice | Consequence at this merge boundary |
| --- | --- | --- | --- |
| Forward, left run in scratch | Take right only when `right < left` | left | The earlier run's equal key is emitted first. |
| Backward, right run in scratch | Take left only when `right < left` | right | The later run's equal key is written into the later output position. |

For example, merging left `[(2,A), (2,B)]` and right `[(2,C), (2,D)]` gives the tie order `A,B,C,D` in either model. The test exercises these local rules and descending-run boundary cases against fixed instruction pins. It does not execute the target and does not by itself prove global sort stability through every partition and small-sort path.

### Four-row base network

At `0x4919588..0x4919655`, the bounded sorter selects pointers to the first four 40-byte rows using unsigned comparisons and copies them into key order; later stores finish the fourth row. The `sort4_network` window pins the complete selection and its associated stores. The generated `small-network-model.tsv` transcribes this one fixed sequence and enumerates all 256 assignments of four ordinal keys to four input positions. Its output agrees with an independently written stable-key ordering for all assignments. Four ordinal key values suffice to represent every possible less/equal/greater relationship among four unsigned keys.

This is a model of the pinned instructions, not a run of the target. As a negative control, changing the model's maximum-pair equality condition from `>=` to `>` breaks 84 of those 256 assignments. The test separately rejects corruption of the real pinned window. A second pinned window shows the analogous four-row selection in the other half. The selected insertion windows shift only for a strictly smaller key; the selected two-ended merge writes the earlier run first at the front and the later run first at the back when keys tie. A separate model combines these observations for lengths 2 through 32. It checks all three-key input vectors through length 8 and four specified patterns at each length 9 through 32: 9933 cases total, all equal to stable ordering. The same tie-condition mutant differs in 4469 of these cases. The model is an interpretation of selected instructions; it does not establish every machine-code path or prove global sort stability. The partition paths and the remaining small-sort instructions still need complete proof.

### Copy comparison and attribution

The long entries differ at 17 byte positions, the run/merge entries at 14, and the partition entries at 24. In each pair all differences lie inside explicitly recorded four-byte PC-relative displacement masks: 8, 6 and 11 masks respectively. The collector checks the instruction prefixes at each mask and rejects any unmasked difference. `evidence.json` lists every masked half-open offset and raw differing offset. This is a selected code-body comparison, not an assertion that the different relocation targets, callee closure, data, or entire ELF are equivalent. The first and second chains have independently validated calls to their own run/merge and partition bodies and to the shared small-sort and pivot FDEs.

### Inference and unresolved points

- The row's first qword is called a size and the following fields user and order ID by the earlier trigger packet. This packet observes their storage positions and unsigned comparisons, not their source names independently.
- Keeping equal-key rows in walk order affects which trigger is submitted first when multiple candidates share a size. That product consequence depends on the selector and firing logic established in the earlier packet; no live matching behavior is observed here.
- The natural-run and merge tie rules support stability at those particular stages. Complete global stability also needs the remaining small-sort network and partition paths proven, including their cleanup and comparator assumptions.
- The allocator and failure-handler targets, all indirect helper implementations, comparator closure, actual triggering/filling, persistent state changes and any third execution instance remain outside this packet.

## Implementation and comparison

Independent Rust: not yet implemented. There is no rebuilt source comparison, no raw or normalized target-to-rebuild byte match, and no claim of ABI or ELF equivalence. The three normalized comparisons above are between target code instances only; masks cover the listed PC-relative displacement fields, not opcodes or branch conditions. The helper, call-target, relocation, vtable/data and whole-ELF closure gaps remain open.

The Python boundary and merge tests are independently stated models tied to fixed byte pins. The input identity, each pin, each listed call, all three pair comparisons, FDE extents, invalid mappings and corrupted branch/relocation inputs have positive or negative controls. They are static controls, not differential behavior against a running node.

## Results and limitations

The collector reads 8 FDE extents totalling 8572 bytes, 32 selected byte windows, 25 calls and 28 selected conditional branches. It emits 27 buffer-boundary rows, 11 run-boundary rows 256 four-row model cases and 31 small-sort model summary rows covering 9933 cases. The focused suite has 17 passing test methods and no skips. These are the studied denominators, not an orderbook function count or reconstruction percentage.

No component completion gate is requested. The complete RE-006 acceptance criterion remains open: this packet does not independently validate a whole insert/cancel/match transition with target-grounded state fixtures. The concrete next question is whether every partition and small-sort path preserves equal-key order for all candidate counts and failures; prove those paths against the recorded bytes before treating overall long-sort stability as established.
