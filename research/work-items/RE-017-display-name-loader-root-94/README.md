# RE-017: display-name loader, action and hash-input paths

Node #94's display-name state readers reject a repeated key after a shared map insertion has replaced its internal value, while a separate action checks for an already-used value before updating the map; a reconstruction can now keep those two duplicate cases and their order distinct.

- Component ID: `abci`, RE-017; bounded display-name path.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only for leads. No reference implementation was copied.
- Claim status: ELF bytes, selected instruction forms, relocation records and destinations are observations; field, type and lifecycle names are inferences below. The action case table is a static model, not captured execution.
- Scope included and excluded: selected JSON and MessagePack display-name value readers, their map insertion and duplicate exits, a primary-layout `setDisplayName` action core and its insertion/removal helpers, and low/shared hash-input writers. Previously studied callers and builder closures are bounded context. The original state-loader GOT and calls, full parser grammar, helper internals, begin/end-block flow, other state fields, node #115 and visor are excluded.

## Reproduce

Run from the repository root with CPython 3.12.3, its standard library, the two existing shared ELF/FDE modules and the authenticated target. Comparison directories must be empty. The generator first checks the complete input SHA-256; it reads the binary as data and writes only `--out`.

```sh
python3 tools/artifacts.py verify
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_display_name94.py --out <tmp-dir>/first
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_display_name94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/first research/work-items/RE-017-display-name-loader-root-94
python3 -m unittest tests.test_abci_display_name94
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-display-name-loader-root-94 && sha256sum -c MANIFEST.sha256)
```

Replace `<tmp-dir>` with a writable scratch directory. To regenerate the retained files directly, use `python3 tools/abci_display_name94.py --out research/work-items/RE-017-display-name-loader-root-94`. Eight generated files are `functions.tsv`, `edges.tsv`, `windows.tsv`, `branches.tsv`, `markers.tsv`, `action-cases.tsv`, `data.json` and `summary.json`; the manifest also covers this README. The generator imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes SHT_NOBITS from file reads, requires a unique file-backed VA mapping and binds each chosen FDE to its unwind-index record. It checks fixed instruction forms and reads `.rela.dyn` and data directly. GNU objdump 2.42 was used only for bounded human inspection; neither the generator nor tests call it or any external program. No target execution, network, keys or chain access is involved.

## Evidence

Addresses are unrelocated ELF linked virtual addresses; file offsets are separately recorded. For example, call `0x361cf6e` has file offset `0x361bf6e`. `functions.tsv` retains full unmasked bytes, SHA-256 and exclusive ends of 25 FDE-described ranges; an FDE does not itself prove a complete function boundary. `windows.tsv` has selected byte windows, some of which end within instructions. `edges.tsv` and `branches.tsv` contain selected complete fixed-form transfers, not a whole-program census. The 12 windows and six edges marked `boundary` connect existing work to newly examined bodies; they do not claim those earlier functions. No original RE-017 GOT or call site is selected. A restricted linear decoder could not complete the MessagePack reader, pair and string ranges because it does not support some instructions; their selected sites were checked by bounded human disassembly, not a complete linear decode.

### Reader paths

The existing [RE-017 state link](../RE-017-abci-state-link-94/README.md) associates a `state.rs` Location with the state loader; [RE-019](../RE-019-rmp-json-loader-94/README.md) identifies its JSON and `.rmp` decode arms. The earlier JSON Exchange dispatch packet in PR #1369 traces the JSON arm through an outer state reader and the Exchange field visitor. Its field visitor is context, not claimed here. At the selected JSON visitor boundary, the duplicate guard targets a diagnostic with the 20-byte `user_to_display_name` label; the nonduplicate value path reaches the new reader at `0x2fe7c37`. The MessagePack visitor's separately selected guard points to the same label and its value path calls the new reader at `0x2abb2af`. `data.json` records the guarded transfers and literal pointer/length setups. The complete MessagePack connection from the original file loader is not independently closed by this packet.

| Selected route | Linked VAs | Observed child sequence |
| --- | --- | --- |
| JSON object | `0x361cc50` | The selected `{` dispatch goes to object handling. Key helper `0x301d7f0`, string reader `0x3097890`, then insertion `0x33a8c70`. |
| JSON array of pairs | `0x361cc50` -> `0x3687600` -> `0x3029660` | Pair key helper `0x30485b0`, value `0x303f000` -> `0x3097890`, then the same insertion `0x33a8c70`. |
| MessagePack fixed map | `0x2b3fee0` -> `0x3676290` | Key helper `0x2a72b70` receives the four-byte label `User`; value reader `0x2c632c0`, then `0x33a8c70`. |
| MessagePack fixed array of pairs | `0x2b3fee0` -> `0x3686e90` -> `0x2d62db0` | Key helper `0x2bd0ea0`, value reader `0x2c632c0`, then `0x33a8c70`. |

The selected JSON table entries for `[` and `{` reach `0x361ccf0` and `0x361cdf6`. On the selected direct MessagePack marker path, the signed-byte test and subsequent comparisons select map markers `0x80..0x8f` and pair-array markers `0x90..0x9f`; the low nibble is the declared count. `markers.tsv` enumerates these 32 conditional cases. Other marker representations, normalized decoder states, subordinate key grammars, escaping and full input languages remain open. The selected child-error, nesting/depth and remainder exits are present in the branch table; they do not establish precedence for every malformed input.

`0x33a8c70` supplies 20 as the compare length at `0x33a8cf0` and calls through slot `0x576e488`, imported as `memcmp`. Under ordinary symbol binding, equality reaches `0x33a8d52`: it copies the previous 24-byte value into the result before writing the incoming 24 bytes into the matching slot. A newly inserted entry increments the count and returns the first-word sentinel `0x8000000000000000`; nonempty-tree structural insertion is delegated. All four selected map callers test the returned first word and construct `duplicate key` on the non-sentinel route. `data.json` reconstructs that text from the four pairs of overlapping immediate stores. Thus, conditional on a valid old value whose first word is not the sentinel, the observed duplicate path follows the replacement. This does not establish that the failed parse publishes the modified temporary map, nor its complete cleanup behavior.

### Selected failure and propagation branches

These are observations on the named paths; neither all malformed-input precedence nor the behavior of delegated helpers is implied.

| Selected condition | Branch and observed destination |
| --- | --- |
| JSON object key helper returns first byte 1 | `0x361ce74` transfers to `0x361d11b`. |
| JSON object reaches a non-colon byte at its colon check | `0x361cee4` transfers to `0x361d4a5`. |
| JSON object string child returns the sentinel first word | `0x361cf09` transfers to `0x361d212`, bypassing insertion. |
| MessagePack direct-map nesting counter is initially zero | `0x2b4028a` transfers to `0x2b405d0`; a nonzero counter decremented to zero transfers at `0x2b40297` to the return-byte-8 path. |
| MessagePack map key or value child returns a byte other than 9 | `0x367633d` or `0x367636e` transfers to `0x3676479` or `0x36764a1`, respectively, before map insertion. |
| MessagePack pair-array child returns 9 but a nonzero remainder survives its count check | At `0x2b40422` the nonzero path subtracts the remainder; when the subtraction does not borrow, `0x2b4042c` writes result byte 4. |
| Either low buffered pair child returns a word different from `0x8000000000000004` | `0x1dd58ba` or `0x1dd58d3` transfers to `0x1dd58e7`, which copies the child result and follows cleanup. |

### Action and hash-input paths

The existing [action dispatch map](../RE-014-action-dispatch-drift/README.md) lists `setDisplayName`; its primary-layout handler reaches `0x4d9b990` through the boundary transfer at `0x4677b80`. The selected wrapper copies the input span, and the new core reads its byte length. A prior builder packet did not assign offsets to the shared table's captures. Here `0x4d7ef4b` stores primary base `+0x4410` in a box; `0x4d7f60f` places that same spilled box beside vtable `0x57448c8` at job-array offset `0xf0` (row 15). The vtable call-slot relocation resolves through thunk `0x4592a80` to previously identified closure `0x4ae4ec0`, whose boundary call reaches new writer `0x45fef60`. `data.json` retains the box, spill, vtable, relocation and thunk bytes. The action's insert and remove calls also pass their primary base `+0x4410`; numerical offset agreement does not prove the calls receive the same base object.

| Condition in the selected action path | Observed result before interpretation |
| --- | --- |
| Input length at least 101 | The prior wrapper stores word `0x143` in its result and takes its wrapper exit; the core is not called. |
| Length 0 | The core calls removal helper `0x4944b50` with base `+0x4410`, then returns word `0x186`, including the helper's no-match sentinel route. |
| Length 1 or 2 | The core returns word `0xd4` before the map walk. |
| Length 21 through 100 | The core returns word `0xd3` before the map walk. |
| Length 3 through 20, equal stored value found | After equal-length comparison through the slot imported as `bcmp`, the core returns word `0xd5` before insertion. |
| Length 3 through 20, no equal stored value found | The core calls `0x493d150` with base `+0x4410`, a 20-byte key and a 24-byte value, then returns word `0x186`. |

These are unsigned byte-length comparisons; upstream text validation and runtime symbol interposition are not established. The 12 rows in `action-cases.tsv` are synthetic boundary cases derived from checked immediates and selected branches, with equal-value outcomes stated as preconditions. They are not node fixtures. The insertion helper compares 20-byte keys and on equality copies out the old value before replacement; on a new entry it increments the count. The removal helper compares the same width, delegates removal on a match, decrements the count, and returns an old value or sentinel. Allocator, rebalancing and nonempty-tree helpers remain boundaries. The selected action comparison scans stored value spans; this packet does not establish all Unicode or string validity rules.

The low named wrapper `0x27b36c0` supplies `user_to_display_name` and tails to `0x25ea910`. The previously identified low row-15 capture is `+0x3990`; its closure also reaches that low writer. The shared writer `0x45fef60` and low writer collect map entries through separate existing helpers, then send pointer pairs to sequence writers `0x440f610` and `0x1e3f470`. Those call pair writers `0x43be050` and `0x1dd5800`; the selected direct pair path emits `0x92` and delegates key and value encoding. Each lane has buffered and direct value paths that pass a pointer and length to existing string writers. The collected order, full encoded stream, subordinate writers, scheduler order and final hash remain open.

### Inferences and unresolved points

The field literals, 20-byte key shape, 24-byte values and compatible offsets support interpreting these as views of a user-to-display-name map. Prior dispatch evidence names the action. Assuming the selected action's state base and the primary builder's base denote the same live object, a successful insert, replacement or removal changes the field captured by row 15; this is conditional composition, not a proof of object identity, actual block ordering or a changed digest. No claim is made that deserialized temporary data reaches that exact live object without copying or intervening writes.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo build scope, compiler/linker flags, two-build comparison, target execution, raw/normalized binary comparisons, complete helper and call-target closure, vtable/data closure, relocation closure and whole-ELF comparison: **not yet measured**. The selected raw bytes are unmasked; there are no normalization masks. Two comparison imports and one closure-call relocation are checked, not all relocations. Tests validate extraction, selected branch models and corruption controls rather than executing the node.

## Results and limitations

`summary.json` reports 25 selected FDE ranges totaling 21,697 bytes, 57 windows (12 boundary), 54 selected transfers (six boundary), 163 conditional branches, four duplicate diagnostics, two JSON table entries, 32 fixed-container marker cases and 12 synthetic action cases. These are packet denominators only. The focused suite passed 28 tests with no skips, including corruption of digest, FDEs, instruction operands, boundary windows, relocation records, value replacement bytes and NOBITS or out-of-range mappings. Two regenerations under different hash seeds and time zones were byte-identical; artifact verification and catalogue checking passed. The repository-wide suite was not run under the stated memory constraint.

No progress gate is requested: ABCI remains 0/4. The full begin/action/end-block and state-root reconstruction remains incomplete. Next question: establish or refute object identity from this decoded field through materialization to the primary action and row-15 capture, including copies and intervening writes, without re-owning existing functions.
