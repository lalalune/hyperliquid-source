# RE-015: checkpoint maintenance modes and the configuration-name error gate

Node #115 uses separate maintenance modes: the count-limited checkpoint path returns after its removal loop, while the archive-pruning path suppresses a later error-log call for configuration bytes 19 and 20.

- Component ID: `constants` (RE-015; checkpoint maintenance is the selected consumer).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is used solely as the optional #94 binary capture.
- Claim status: selected byte observations and conditional inferences; complete component behavior is unresolved.
- Scope included and excluded: one caller, two maintenance modes, selected checkpoint/marker/selection helpers, the name-gated error path, selected unwinding entries, and explicit #94 comparisons. Formatter internals, operating-system calls, date helper internals, the first archive helper, all other callers, and complete sorting and component control flow are boundaries.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3 or a compatible Python 3 with the standard library:

```sh
python3 tools/node115_evm_prune_policy.py --out research/work-items/RE-015-evm-prune-policy-115
python3 -m unittest tests.test_node115_evm_prune_policy
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
PYTHONHASHSEED=7 TZ=UTC python3 tools/node115_evm_prune_policy.py --out <tmp-dir-a>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/node115_evm_prune_policy.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Replace each bracketed temporary-directory placeholder with a separate writable directory. The collector hashes `artifacts/node/115/hl-node` before parsing. It uses repository `tools/elf_index.py` and `tools/fde_extents.py`, Python `struct`, and fixed opcode patterns; it invokes no external program and does not execute the captured node. `MANIFEST.sha256` records the retained files' hashes. The output contains selected raw instruction/data windows, relocation operands, FDE extents, and case models; it is not a disassembly or a complete function census.

The following optional comparison requires a separately supplied, authenticated #94 artifact. It prints its raw comparison as JSON after the #115 summary; the default generation and tests do not require #94:

```sh
python3 tools/node115_evm_prune_policy.py --out <tmp-dir> --compare-94 <node94-artifact>
```

## Evidence

Coordinates below are linked ELF virtual addresses (VA); section-derived file offsets, raw bytes and full FDE body hashes are in the generated tables. An FDE range is an unwind range, not proof of a complete function census. Function labels are descriptive inferences, not recovered symbols. Selected references to earlier-owned functions are boundaries: `RE-015-static-config-path-115` (#2042) and `RE-015-config-path-115` (#2054) cover `0x17780c0`, `0x17783e0`, and the classifier; `RE-015-name-gated-cleanup-115` (#2116) covers predicate `0x1500a60` and removal helper `0x1561530`.

| Selected FDE start | Observation |
| --- | --- |
| `0x2dd4f10` | Caller passes the low bit of its byte at offset `0x30` to `0x4d98c40`; if maintenance and intervening cleanup return normally, it writes `1`, `0`, and a stack-derived pointer to the object at offsets `0x18`, `0x20`, and `0x28`, then decrements its reference count. Pointer lifetime and higher-level state meaning remain unresolved. |
| `0x4d98c40` | A zero mode passes immediate `100` to `0x38c51f0` and then reaches release directly. A nonzero mode performs date checks, calls `0x38c40f0`, and then calls `0x38c56f0`. The raw mode-dependent jumps are in `windows.tsv`. |
| `0x38c51f0` | The reader result enters a small ordering helper for counts 2–20 and a large ordering helper for counts at least 21. Selected paths are collected, tested through the existing predicate boundary, and may be passed to the existing removal boundary. |
| `0x4468e30`, `0x1696b90` | The reader references the complete `/checkpoint` template, parses a supplied final component as an unsigned decimal value, and checks complete-marker templates, including the typed `EvmState` form. |
| `0x3d5dab0`, `0x37c1330` | The selected collection path skips a requested count and copies the remaining path portions. Its boundary record has a special signed-minimum tag; the simple count model assumes ordinary tags. |
| `0x436cb90`, `0x36f2690`, `0x3e3f6f0`, `0x42edcb0` | The small path compares the unsigned key at record offset `0x18` in descending order. The selected large forward and backward merge comparisons pick the larger key for the front and smaller key for the back respectively. The whole large-order implementation is not closed. |
| `0x38c56f0`, `0x3d5dca0` | Archive pruning checks marker and candidate paths. Its selected filter accepts a true `/MARKED_FOR_DELETION` test; otherwise it accepts only the interval and cap shown below. Removal is a separate later call boundary. |
| `0x1564120` | On a nonzero archive-prune return, the caller reaches a configuration-byte gate before a log boundary and an indirect first-vtable-entry call. |

The two normal-return routes are distinct (`flow-cases.tsv`):

| Mode bit | First operation and failure | Follow-on operation |
| --- | --- | --- |
| 0 | Count pruning with argument 100; a nonzero result reaches its own log boundary and first-vtable-entry call. | Both the zero and nonzero first results jump to release; archive pruning is not called on this route. |
| 1 | Date preparation precedes the first archive boundary. Its selected error sentinel reaches an archive-specific log and first-vtable-entry call; its ordinary result follows a cleanup path. | On normal returns, both routes call archive pruning. A nonzero result reaches `0x1564120`; zero proceeds to release. |

At `0x4d98c88`, a zero first date result reaches the length-delimited literal `` Local time out of range for `NaiveDateTime` ``. At `0x4d98c9b`, after the next helper receives `0xffffffff`, a zero result reaches the literal `` `NaiveDate - TimeDelta` overflowed ``. Both converge on a call to `0x1680bd0`, followed by `ud2` if that boundary returns. `date-cases.tsv` models these checks only after normally returning preceding helpers; it does not predict the clock or calendar results.

The reader's selected numeric loop accepts decimal ASCII with an optional leading plus, rejects an empty component, minus and nondigits, and rejects values above `2^64-1`. Seventeen or more post-plus bytes use the checked multiply/add path. This is conditional on the preceding component-extraction helper returning those bytes; it is not a complete path grammar. For ordinary records the count model selects `max(n - 100, 0)` tail path portions; for example, 99 and 100 produce zero, while 101 produces one. The source records have a 32-byte stride and the copied path portions have a 24-byte stride. The selected small and large comparisons support a descending-order interpretation, but the large path's complete ordering and stability have not been proven.

At the archive filter, when the marker test is false, the selected unsigned comparisons accept `lower <= height < upper` and `height <= max_height`. The three bounds are caller-supplied operands; this packet does not assign them calendar meanings. A true marker test reaches selection without those comparisons. The reader and archive scanner pass marker strings to a predicate at `0x1500d20`; the underlying operating-system semantics and effects are not established here. A nonzero removal-helper result reaches its first vtable entry before the normal-return loop continues. The exact destructor implementation and the eventual outcome of a removal are boundaries.

The name gate loads the byte at global object offset `0x48` and executes bytes `0fb6434804ed3c017679` at `0x156413b` (file offset `0x156313b`): `(byte - 19) mod 256 <= 1` skips the log call at `0x15641b8`. The selected bytes are exactly 19 and 20 across all 256 possible input bytes. On either gate branch, normal control reaches the first-vtable-entry call at `0x15641c5`. The earlier classifier mapping and this capture's selected relocated descriptors associate those positions with `SoloTestnet` and `SoloMainnet`; the adjacent table positions are `Ee` at 18 and `LockerTestnet` at 21, while `NvTestnet` is at 33. The binary diagnostic contains the bound 79; this is a separate observation from the arithmetic behavior on all byte values. A log boundary call is not proof of an emitted message.

The selected `.eh_frame` call-site tables contain 103 entries in total, mapped to the 14 selected FDE ranges in `exception-sites.tsv`. `exception-edges.tsv` shows, for example, the selected caller's maintenance-call landing at `0x2dd5070`, the count removal landing at `0x38c56b1`, the archive removal landing at `0x38c64d9`, and the name-log landing at `0x1564203`. Action values are retained as encoded; the complete language-specific action table and every unwind branch are not interpreted.

### Historical anchors, kept release-specific

The optional comparison authenticates #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` separately. For `/cham`, #94 entry/reference VAs are `0x1fc0ec`/`0x164f840`; #115 entry/reference VAs are `0x44ab69`/`0x17780f3`. For `/static_config`, they are `0x1ef5f5`/`0x164fbae` and `0x4401ef`/`0x177840e`. The references address the complete template starts, not rendered paths. Reference file offsets and raw bytes are in the optional comparison JSON and the #115 `pools.tsv`.

The sampled #94 gate at `0x13cbcf7` (file offset `0x13cacf7`, FDE `0x13cbce0`–`0x13cbda8`) uses `0fb64348247e3c127448`, giving raw-byte matches 18, 19, 146 and 147. Its `0x13cbd2b` reference and the #115 reference at `0x1564174` point to identical complete archive-prune error templates; the old branch bypasses its log boundary and reaches the first-vtable-entry call. The independently read #115 gate gives 19 and 20. The historical named-domain positions for `SoloTestnet`, `SoloMainnet`, and `NvTestnet` are 18, 19 and 32; their selected #115 descriptor positions are 19, 20 and 33. This is a three-name comparison, not a resubmission of the historical discriminator table. Existing #115 path and classifier work remains the owner of those routines.

The illustrative `global_constants/static_config.rs` reference assigns `NvTestnet` the position 32 and calls it a fallback. That position agrees with the selected #94 descriptor and differs from the selected #115 descriptor. This packet does not infer the #115 missing-input fallback from the illustrative file or reanalyze the existing fallback function; the reference is a lead, not implementation evidence.

The raw second JSON line from the optional comparison was:

```json
{"gate_error_context": {"entry_hex": "287072756e655f65766d5f636865636b706f696e74735f69665f746172726564206661696c65643a20c000", "new_bypass_va": "0x15641be", "new_entry_file_offset": "0x442eed", "new_entry_va": "0x442eed", "new_log_va": "0x15641b8", "new_reference_file_offset": "0x1563174", "new_reference_va": "0x1564174", "old_bypass_va": "0x13cbd49", "old_entry_file_offset": "0x1f2cba", "old_entry_va": "0x1f2cba", "old_log_target_va": "0x143d010", "old_log_va": "0x13cbd43", "old_reference_file_offset": "0x13cad2b", "old_reference_va": "0x13cbd2b"}, "name_samples": [{"new_relocation_file_offset": "0xd7a0", "new_slot_va": "0x63f88b8", "new_tag": 19, "new_text_va": "0x4646a0", "old_relocation_file_offset": "0xe0a8", "old_slot_va": "0x56683a8", "old_tag": 18, "old_text_va": "0x218089", "text": "SoloTestnet"}, {"new_relocation_file_offset": "0xd7b8", "new_slot_va": "0x63f88c8", "new_tag": 20, "new_text_va": "0x4646ab", "old_relocation_file_offset": "0xe0c0", "old_slot_va": "0x56683b8", "old_tag": 19, "old_text_va": "0x218094", "text": "SoloMainnet"}, {"new_relocation_file_offset": "0xd8f0", "new_slot_va": "0x63f8998", "new_tag": 33, "new_text_va": "0x464716", "old_relocation_file_offset": "0xe1f8", "old_slot_va": "0x5668488", "old_tag": 32, "old_text_va": "0x2180ff", "text": "NvTestnet"}], "new_byte_cases": [19, 20], "new_gate_fde_end": "0x156421d", "new_gate_fde_start": "0x1564120", "new_gate_file_offset": "0x156313b", "new_gate_hex": "0fb6434804ed3c017679", "new_gate_va": "0x156413b", "new_sha256": "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301", "old_byte_cases": [18, 19, 146, 147], "old_gate_fde_end": "0x13cbda8", "old_gate_fde_start": "0x13cbce0", "old_gate_fde_va": "0xfc5ef0", "old_gate_file_offset": "0x13cacf7", "old_gate_hex": "0fb64348247e3c127448", "old_gate_va": "0x13cbcf7", "old_sha256": "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f", "pools": [{"entry_hex": "c0052f6368616d00", "name": "cham", "new_entry_file_offset": "0x44ab69", "new_entry_va": "0x44ab69", "new_reference_file_offset": "0x17770f3", "new_reference_hex": "488d356f2acdfe", "new_reference_va": "0x17780f3", "old_entry_file_offset": "0x1fc0ec", "old_entry_va": "0x1fc0ec", "old_reference_file_offset": "0x164e840", "old_reference_hex": "488d35a5c8bafe", "old_reference_va": "0x164f840"}, {"entry_hex": "c00e2f7374617469635f636f6e66696700", "name": "static_config", "new_entry_file_offset": "0x4401ef", "new_entry_va": "0x4401ef", "new_reference_file_offset": "0x177740e", "new_reference_hex": "488d35da7dccfe", "new_reference_va": "0x177840e", "old_entry_file_offset": "0x1ef5f5", "old_entry_va": "0x1ef5f5", "old_reference_file_offset": "0x164ebae", "old_reference_hex": "488d3540fab9fe", "old_reference_va": "0x164fbae"}]}
```

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo graph, compiler comparison, binary matching, normalized masks, fixture execution, whole-ELF comparison, or helper/data/vtable closure is claimed. Relocation closure is limited to the selected pointers in `relocations.tsv`. The optional cross-release comparison preserves the two input digests and independent VA/file coordinates; it establishes selected byte facts, not equivalence of the releases.

## Results and limitations

The collector authenticates one #115 input and emits 19 deterministic evidence files: 14 selected FDE ranges totaling 14,880 bytes, 49 selected raw windows, 116 selected conditional branches, 46 selected call sites, 103 encoded call-site entries, 28 selected relocations, 15 selected literal/template references, and six selected name descriptors. These are selected-set counts, not coverage denominators. The 30 focused tests include wrong digests, changed instruction bytes, malformed/duplicate relocation and LSDA records, unmapped and zero-fill addresses, decimal overflow, unreachable mode/date combinations, and exhaustive 256-byte name and two-byte numeric cases. The executable is never run.

The first archive helper, complete large-sort control flow, full marker predicate and removal effects, caller ownership, and all other paths remain open. No component gate is requested. Next question: resolve the remaining large-sort handoff and trace how the archive filter's three bounds are populated, using #115 bytes and independently owned function ranges.
