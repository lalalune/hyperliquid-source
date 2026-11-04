# RE-010: node 115 setReferrer decode, dispatch and state path

Node #115's `setReferrer` tag `0xa0` reaches a shared state core through direct and nested static dispatch paths, and its missing-profile branch returns `0x1a2` without the final binding write.

- Component ID: `action-dispatch` (task `RE-010`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only to locate a question, not as implementation source.
- Claim status: static observations and explicitly marked inferences; runtime transfer and several callees remain unresolved.
- Scope included and excluded: the selected referral decode and state path, including a nested `MultiSigAction` layout; no captured execution, live network, Rust implementation, or component completion claim.

## Reproduce

From the repository root, after adding the packet files:

```sh
python3 tools/re010_set_referrer_115.py --out research/work-items/RE-010-set-referrer-path-115
python3 -m unittest tests.test_re010_set_referrer_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-set-referrer-path-115 && sha256sum -c MANIFEST.sha256)
```

The input is `artifacts/node/115/hl-node`. The generator authenticates its complete SHA-256 before parsing. It uses Python 3 standard library, `tools/elf_index.py`, and `tools/fde_extents.py`; it neither executes the target nor calls external programs. The observed environment was Python 3.12.3 on Linux x86-64. Generated files and this README are hashed in `MANIFEST.sha256`; the generator updates the generated files only. Generated records contain no wall-clock time or machine-specific paths.

`functions.tsv` records complete selected FDE byte windows and their SHA-256 values. `windows.tsv`, `branches.tsv`, `calls.tsv`, `constants.tsv`, `literals.tsv`, `switches.tsv`, `payload-key-kinds.tsv`, `name-precedence.tsv`, and `relocations.tsv` preserve the selected raw instruction/data evidence. `summary.json` gives counts of those selections. Synthetic model inputs and comparisons are kept in the focused tests and are not captured node behavior.

## Evidence

All addresses below are linked ELF virtual addresses; file offsets are zero-based. For example, the selected core starts at VA `0x3c17590` and file offset `0x3c16590`. The tool resolves file-backed sections, rejects `SHT_NOBITS`, verifies FDE entries against the unwind index, checks body hashes and decodes the selected relative calls, branches, jump-table entries and relocations directly from ELF bytes. Selected instruction sites were discovered by static disassembly; the generated records do not parse disassembler output. A listed FDE extent is an unwind range corroborated here by calls and instruction analysis, not proof of a one-to-one original Rust source function.

### Newly examined FDE ranges

End addresses are exclusive; roles are descriptive and not recovered symbols.

| Role | Start | End |
| --- | --- | --- |
| Outer action decoder | `0x3a01c70` | `0x3a02f72` |
| Multi-party payload decoder | `0x3a1f060` | `0x3a200b6` |
| Boxed action decoder | `0x3b92540` | `0x3b925ea` |
| Action decoder | `0x36b8c90` | `0x36baeec` |
| Action envelope | `0x3960480` | `0x39618bb` |
| Name input adapter | `0x3b68540` | `0x3b68655` |
| Referral payload decoder | `0x39ef520` | `0x39efd0d` |
| Referral state core | `0x3c17590` | `0x3c17fb9` |
| Compact code search | `0x455c290` | `0x455c503` |
| Compact profile search | `0x4556550` | `0x4556717` |
| Compact history search | `0x455a260` | `0x455a42b` |
| Compact history insertion | `0x4546480` | `0x454657e` |
| Compact history shift | `0x456d220` | `0x456d493` |
| Empty-tree insertion | `0x3705790` | `0x37058d0` |
| Temporary status cleanup | `0x3d08df0` | `0x3d0913a` |

The formatter, routers and first-call wrappers mapped in the retired #115 `RE-014-action-dispatch-drift` packet at commit `ed15cdefc503ba2d845939fe7b65bd58b6202c59` are re-read as **context**, not counted as newly examined FDEs. The reference's agent-created `set_referrer` handler file is a navigation clue; in #115 the direct first-call wrapper, nested wrapper, shared state core and container helpers occupy distinct ranges. Conversely, an FDE range does not establish that any one of those ranges was a distinct function in the original source.

### Name, tag and direct dispatch

The selected name matcher at `0x36616b0` first switches on length; length 11 selects table entry `0x79932c` and arm `0x3661efc`. The arm tests two preceding 11-byte candidates, `batchModify` and `createVault`, then compares two overlapping eight-byte windows covering all of `setReferrer`. The equal branch at `0x3661f69` reaches `0x36626a9`, which writes ordinal `0x1a`; the success tail writes zero to the result's leading byte. `name-precedence.tsv` reconstructs all three comparison operands, including the signed adjustment used for the first one.

The selected input kinds 12 and 13 in adapter `0x3b68540` call this matcher. On the recorded success path, `0x3960480` saves the returned ordinal, and action decoder `0x36b8c90` uses it as table index 26. Its entry at `0x79a414` reaches `0x36ba91b`, references `SetReferrerAction` and the relocated `code` descriptor, calls `0x39ef520`, and stores internal success tag `0xa0`; its selected error arm stores `0xe2`. The serializer's separately measured index 26 emits `setReferrer`.

For this tag, the established bias `0x86` gives index 26. The direct router entry `0x609f68` leads to arm `0x2bdb019`, whose call at `0x2bdb029` reaches wrapper `0x2c1b320`. The nested router entry `0x60a3c8` leads to `0x2bdc781`, whose call reaches wrapper `0x23853b0`. Both wrappers use RIP slot `0x64e50b0`; the ELF's `R_X86_64_RELATIVE` record for that slot has addend `0x3c17590`. This establishes the static relocation association, not a runtime binding or an execution capture.

### Nested layout and transfer points

For `MultiSigAction`, the same action decoder selects index 52 and stores tag `0xba`. Its arm calls `0x3a01c70`; a seven-byte `payload` comparison selects field index 2 and a call to `0x3a1f060`. The latter compares `multiSigUser`, `outerSigner`, and `action`; on selected map and sequence paths its `action` value reaches `0x36b8c90` directly or through `0x3b92540`. The selected successful sequence path returns the boxed action pointer in the first word, and `0x3a02a44` stores that pointer at outer decoder result offset `+0x18`. The outer action decoder copies the result after its tag.

Independently, the context direct router selects its index-52 arm and calls `0x2c12690` with the action payload after the tag. After recorded gate calls succeed, that wrapper calls the nested router `0x2bdbaa0`; the nested router loads the pointer at payload offset `+0x18` and dispatches the pointed-to tag. Thus the measured producer and consumer offsets agree on this path. The runtime handoff between a decoded outer action and this router is not established here; this is a structural compatibility observation, conditional on that handoff and on the selected success paths.

### Payload and wrapper failure branches

The referral payload decoder accepts selected input-kind branches `0x14` and `0x15`; other kinds go to a separate error-construction call. For kind `0x15`, the field-key visitor has 15 bounded switch entries, all recorded in `payload-key-kinds.tsv`. Two selected string-key arms compare length 4 and the bytes `code`; unknown names go to a separate helper. The initial missing-field path and the repeated-field path reference distinct `missing field` and `duplicate field` format prefixes. The kind `0x14` path has distinct zero-item and extra-item branches, and both selected kinds call the same value-conversion helper. The `MapAccess::next_value` ordering panic is a separate internal path. Other input kinds, value conversion details, allocation failures and unwind cleanup are not exhaustively characterized.

Both referral wrappers compare the passed code length with 101: lengths below 101 take the core-call branch; 101 and above produce word `0x158`. The direct wrapper also has an earlier identity-related path producing word `0x120` and calls two shared gates whose non-`0x1a2` results are propagated. On a returned core word `0x1a2`, the wrapper writes outer tag `0xe`; other returned words take outer tag `0xf`. These values are internal result representations, not asserted public API error codes.

### State transition and selected failures

The following names are **inferences** from the observed 20-byte keys, `code` lookup, and write sites. The table gives the observed branch order for selected normal paths; it does not assert the full behavior of the helpers or corrupted state.

| Ordered condition | Word | Observed consequence |
| --- | --- | --- |
| Code lookup misses | `0xa6` | Returns before the entry helper. |
| Found 20-byte owner key equals input key | `0xa2` | Returns before the entry helper. |
| Entry result byte `+0xc4` is nonzero | `0xa3` | Returns after entry helper; no final binding write. |
| Owner profile lookup misses | `0x1a2` | Returns without the final binding write. |
| Profile exists, bucket width is zero | `0xa5` | Returns without the final binding write. |
| Same bucket and remaining count is zero | `0xa5` | Returns without the final binding write. |
| Selected eligible path | `0x1a2` | Updates the counter and history, writes `1` at entry `+0xc4`, and copies the 20-byte owner key at `+0xc5`. |

The entry helper is called before the profile lookup. Its side effects are not closed, so “no final binding write” does not mean that no state changed. On an eligible new bucket, the observed unsigned comparison chooses `max(configured, 1000)` before decrement; in the same bucket, a positive remaining count is decremented. The one temporary `0xa5` cleanup switch entry reaches a direct return, a claim limited to that input.

The selected time arithmetic reads a signed packed year and an ordinal field, derives a day count, multiplies by 86400 and 1000, adds a nanosecond-derived fraction, clamps negative milliseconds to zero, and divides by nonzero bucket width. A 32-bit divide is used only when both operands fit in 32 bits; otherwise a 64-bit divide is used. The implementation in the tool is a synthetic interpretation of these instructions, checked independently against standard-library Gregorian dates and an integer calendar formula; it does not establish that arbitrary packed values are valid inputs.

The selected 20-byte-keyed history search has compact and tree representations. A compact record occupies 32 bytes; a match replaces the 12-byte time field, while a selected missing-key path calls compact insertion. The sentinel/tree representation is eligible for a conversion when count is below 32; the compact path attempts the reverse conversion for an absent key at count at least 64. The empty-tree helper allocates 368 bytes and copies the 20-byte key and 12-byte value, with a recorded node limit of 11. The conversion helpers and nonempty-tree insert are boundaries, not closed implementations. Failure after the counter update, allocator behavior, unwind rollback and invariant preservation remain open.

### Historical lead and separation

The retired #94 `RE-010-exchange-handlers` packet at commit `6bc048d44945e8948538d0cda2d92712eb29fab9` described case 25/tag `0x8d`, arm `0x27599b4`, and first call `0x27de270` for `setReferrer`, bound to #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. That packet is a lead only. Here the #115 name matcher, selected decode arm, serializer and dispatch entries were independently read from #115 bytes, yielding index 26/tag `0xa0` and the #115 coordinates above. The #94 binary was not available for a new byte comparison, and no cross-release body or layout equivalence is claimed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker flags, two-build comparison, normalized masks, helper closure, vtable/data closure and whole-ELF comparison: **not yet measured**. No source-equivalence or binary-equivalence claim is made.

The focused tests include wrong and corrupted digests, mutated code/table/relocation bytes, out-of-range and ambiguous addresses, `SHT_NOBITS`, a changed field name, each single-byte change to the selected action name, the missing and duplicate field branches, counter thresholds, date boundaries and 32/64-bit division selection. The synthetic transition model assumes successful unmodeled helpers; it is not a target oracle and cannot establish transactional rollback or acceptability of malformed inputs.

## Results and limitations

The generated summary counts 15 selected FDE ranges, 90 selected instruction windows, 126 selected branch sites, 44 direct and 14 slot calls, 10 selected switch entries, all 15 entries of the bounded payload-key switch, and 8 selected relocation records. These are denominators for the selected evidence only, not a function census or a coverage percentage. The focused suite passed 63 tests with zero skips; the generator was compared across two hash seeds and time zones with a binutils-free `PATH`. Artifact verification and the catalogue check passed. No full test suite or node execution was performed.

The decoder-to-router runtime transfer, parser ownership, earlier gates, arbitrary input forms, nonempty-tree and conversion helper semantics, allocation failure and unwind rollback, and other dispatch variants remain open. No `action-dispatch` gate is requested; the component remains 0/4. The next question is whether the producer's decoded action object reaches the recorded router without an intervening layout transformation, followed by target-grounded closure of the history conversion and failure paths.
