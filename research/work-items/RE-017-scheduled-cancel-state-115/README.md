# RE-017: scheduled-cancel state from loading to snapshot and root input

This packet connects node #115's `user_to_scheduled_cancel` read, materialization, representation-specific clone and expansion to its snapshot writer and root-input visitor, giving an independent reconstruction the conditional field offsets, duplicate rules and failure decisions for this path.

- Component ID: `abci`; the state, snapshot and root question advances RE-009, using the historical RE-017 lead.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation lead only. No unlicensed reference code was copied.
- Claim status: original bytes, FDE records, selected instruction targets, relocations and literals are observations; names, conditional joins and branch models are inferences. Unknowns are explicit below.
- Scope included and excluded: one named state field across selected JSON and binary input paths, map completion, the selected compact and tree clone branches, expansion, two snapshot value writers and one root-value visitor. The complete state schema, all action and end-block cases, source-level types, final root digest, runtime reachability and component gate are excluded. The previously studied loader, parent visitors, materializer, startup constructor, root map visitor, snapshot serializer, GOT slots and their already reported call sites remain context.

## Reproduce

From the repository root with the authenticated target, Python 3.12.3 and the existing `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/abci_cancel_state115.py --out research/work-items/RE-017-scheduled-cancel-state-115
python3 -m unittest tests.test_abci_cancel_state115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
: "${TMPDIR:?Set TMPDIR to a writable temporary directory}"
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_cancel_state115.py --out "$TMPDIR/cancel-a"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_cancel_state115.py --out "$TMPDIR/cancel-b"
diff -r "$TMPDIR/cancel-a" "$TMPDIR/cancel-b"
diff -r --exclude=README.md --exclude=MANIFEST.sha256 "$TMPDIR/cancel-a" research/work-items/RE-017-scheduled-cancel-state-115
(cd research/work-items/RE-017-scheduled-cancel-state-115 && sha256sum -c MANIFEST.sha256)
```

Use fresh empty output directories. The optional cross-release check authenticates the separately supplied historical ELF and prints the old and new coordinates without changing generated #115 evidence:

```sh
python3 tools/abci_cancel_state115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out "$TMPDIR/cancel-history"
```

The generator checks the full #115 digest before producing output, imports the repository's shared parsers, excludes `SHT_NOBITS` from file-backed mappings, and reads section, FDE, relocation, dynamic-symbol, literal, instruction and table bytes directly. The optional historical input is separately authenticated. Neither generator nor tests invoke external programs or the target; they work with Python as the only executable on `PATH`. GNU objdump 2.42 was used only for human inspection of selected instructions. Files in this packet contain no objdump output. No node, visor, network, key or chain action was used.

`functions.tsv` contains selected FDE coordinates, offsets and raw-body hashes; `windows.tsv`, `transfers.tsv`, `branches.tsv`, `relocations.tsv`, `imports.tsv` and `literals.tsv` retain exact selected bytes or records. `json-dispatch.tsv` decodes the guarded table directly. `layout.json` records offsets and checked copy-range arithmetic; `summary.json` counts selected observations. The remaining case tables are synthetic models of the stated guards, not observed executions. `MANIFEST.sha256` covers the README and every generated file.

## Evidence

Coordinates are unre-based ELF virtual addresses; the generated records also contain file offsets. FDE ends are exclusive, and an FDE is an unwind extent rather than proof of source boundaries or all control flow. Selected windows and transfers outside the listed new FDEs are labelled `prior-boundary`; they explain the field's joins, not ownership of those functions. No instruction census or whole-component denominator is claimed.

The previously reported RE-017 loader handoff reaches the Location record at `0x64767a8`, `l1/src/abci/state.rs:123:37`, and the RE-009 read packet follows the text and binary outer decoders. In that text path the earlier reader reaches the exchange visitor `0x3efb050`; the selected field continuation at `0x3efdb57` calls new FDE `0x3c741e0`. In the binary path the previously identified child `0x32caf70` calls the field-containing visitor at `0x32cb0dc`; its selected continuation at `0x2fd8b73` calls new FDE `0x336ff60`. The old loader GOT and call sites are not newly owned.

| Stage | Selected #115 observations |
| --- | --- |
| Top-level field guard | In the JSON and binary visitors, `0x8000000000000001` initializes the local field word. A second occurrence takes separate duplicate-field paths. At map completion the unchanged sentinel selects an error using the `user_to_scheduled_cancel` literal; a present field continues. A child error is handled separately. These statements apply to the selected map branches and after earlier required-field checks. |
| JSON container | `0x3c741e0` uses a 33-entry signed-relative table at `0x7b3f00`. The `[` entry selects `0x37b12c0` and the `{` entry selects `0x374f340`; both have checked depth guards and distinct child/error continuations. Pair-array decoding reaches `0x3f6c790`, while the object route uses `0x421a240` and `0x3f4b160`; the selected key buffers are 20 bytes and both reach value reader `0x40758a0`. |
| Binary container | On the fresh-marker arm, `0x80..0x8f` selects a map and `0x90..0x9f` selects an array, with low-nibble counts. The map route uses `0x373e700`, the `User`-labelled key boundary `0x2f660a0`, and value reader `0x31c9130`; the pair-array route uses `0x3769fe0` and `0x31ec530` to reach the same value reader. Zero and decrement-to-zero depth cases branch separately. Other marker forms are not characterized here. |
| Value fields | The selected named value readers recognize `t` and `n` and guard each with an independent seen flag. A second occurrence fails even when the first decoded value was zero or null. Missing `n` gives zero and missing `t` gives a zero option word. JSON `null` for `t` is checked in `0x45173d0`; the selected binary nil marker is `0xc0`. The value's count is at `+0`, its option word at `+8`, with additional option payload bytes not fully decoded here. Unknown fields and primitive helper behavior are boundaries. |
| Loader output | On selected normal returns, the JSON and binary visitor each place the 32-byte map representation at visitor-result `+0x2488`. The JSON parent copies from a child payload starting `+0x10` into its result starting `+0x10`; its later full-size copy retains `+0x2488`. On the selected binary parent map route with zero remaining count, three checked copy ranges also retain `+0x2488` in its parent result. `layout.json` records the operands and projections; child failures, depth failures and remaining-count underflow take other branches. |
| Materialization | In the previously reported materializer `0x3c2e860`, selected straight-line loads at `0x3c2ed5e` read input `+0x2488` and `+0x2498`; stores at `0x3c2edb3` write the two 16-byte blocks at output `+0x3fa8` and `+0x3fb8`. This is an added field projection inside the existing boundary, not a claim on the materializer FDE. |
| Clone and expansion | The previously studied clone `0x55ea030` tests the representation word at input `+0x3fa8`, invokes the compact or tree clone boundary, packs the returned representation, and stores 32 bytes at clone output `+0x3fa8`. In the existing expansion `0x548ce30`, the field is copied from input `+0x3fa8` to stack `+0x6238`; the allocated output is copied from stack `+0x1720`, so the field is at output `+0x4b18`. |
| Snapshot | The prior snapshot serializer passes state `+0x4b18` at `0x548209c` to new map writer `0x5673cd0`; its selected pair-writing chain reaches `0x4d935f0` or `0x4d933e0`. The named writer refers to `t` and `n`; in the selected binary named-field arm, successful two-byte writes produce `a174` and `a16e`. Both value writers include `t` when the dword at value `+8` is nonzero and `n` when the qword at `+0` is nonzero, in that order. Child-encoder and buffer failures exit separately, and rollback is not established. |
| Root input | Prior root job 21 captures state `+0x4b18` and supplies descriptor `0x64a8408`, whose relative relocation points to the existing map visitor `0x4d9df80`. Selected context in that visitor supplies 20-byte key descriptor `0x649a790` and 24-byte value descriptor `0x649c7b8` for entries of stride 48, with value at entry `+24`. The value descriptor points to new visitor `0x3d38b00`, which supplies the value at `+8` with option descriptor `0x64787f8` and at `+0` with the eight-byte descriptor. Option visitor `0x4513370` chooses distinct descriptors for zero and nonzero words. The generic visitor and final digest remain boundaries. |

### Duplicate completion and storage branches

The four selected JSON and binary collection routes reach `0x3cbc860` after accumulating 48-byte records. Its count and adjacent-comparison branches are:

| Count or condition | Selected consequence |
| --- | --- |
| 0 or 1 | No ordering helper is called before the adjacent check. |
| 2 through 20 | Call `0x4371920`. Its selected instructions compare 20 bytes through a slot whose ELF dynamic symbol is `memcmp` and shift 48-byte records. Ordinary dynamic binding and normal return are assumptions. |
| 21 or more | Call a relative-relocation slot targeting `0x36feb50`; that adapter delegates to `0x3eb38d0`. Its full ordering implementation is a boundary. |
| Adjacent equal keys | The selected SIMD comparison covers 16 bytes and the following 4 bytes. Equality returns `0x8000000000000001`, with a conditional temporary-buffer release; selected callers format `duplicate key`. Detecting all duplicates assumes the ordering helper has placed equal keys together. |
| No equal adjacent keys, count at most 64 | Call compact-storage helper `0x45695a0`. |
| No equal adjacent keys, count above 64 | Call separate helper `0x38935e0`. |

The output does not assert how an invalid in-memory header is handled or that either storage helper implements a particular Rust collection. The large-sort adapter's stack/heap choice is based on its computed capacity, not directly on the original map count.

### Clone, failure and field projections

The clone's marker comparison selects a compact helper when its first word differs from `0x8000000000000000`. On the sentinel arm, zero at input `+0x3fc0` selects an empty path; a nonzero value with a nonzero pointer at `+0x3fb0` calls the recursive tree helper. A null pointer on that selected nonempty arm branches to a failure path. The compact helper `0x5844190` reads a count at its input `+0x18`, allocates at a 48-byte stride, and checks the count against `0x2aaaaaaaaaaaaaa` before the allocation path; zero size takes a separate raw-8 path and a null nonzero allocation enters an error call. Its cursor and element-copy helpers are not fully reconstructed.

The selected recursive helper `0x522ea30` branches on its level argument, allocates `0x250` bytes in the internal-node arm or `0x1f0` bytes in the leaf arm, and has separate null-allocation exits. Selected leaf instructions load 20 key bytes and value words, advance the source key by 20 and value by 24, and check a 16-bit output node length against 11 before adding an entry. A full node takes a failure call followed by `ud2` if the call returns. The tree structure, allocation semantics, all cleanup and iterator behavior remain outside this packet.

The #115 RE-010 schedule-cancel core packet separately observes writes to the map at compact state `+0x3fa8`; this packet does not re-own its action functions. If that selected state is the loader result supplied to the reported constructor, calls return normally, the copy import has ordinary semantics, the clone helpers preserve their logical entries, and no intervening alias writes replace the field, the newly checked projections carry that field through clone output `+0x3fa8` into expanded state `+0x4b18`. The same conditions apply when joining the earlier startup and root jobs. Runtime object identity, every intervening helper effect, and a later scheduled action on that object are not independently established by static offsets alone.

For a human-readable example of the byte-backed projection, the selected instructions are equivalent to:

```text
0x3c2ed5e  lea input+0x2488; load two 16-byte blocks
0x3c2edb3  store those blocks at output+0x3fa8 and output+0x3fb8
0x548d233  load input+0x3fa8 and input+0x3fb8
0x548d241  store at stack+0x6238 and stack+0x6248
0x548d83f  select stack+0x1720 as the 0x4e38-byte output source
```

These are selected operations; `windows.tsv` retains the original bytes. The projection `0x6238 - 0x1720 = 0x4b18` is also range-checked by the generator and negative-control tests.

### Release-specific cross-check

The historical RE-017 state-link record is bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, with `state.rs:107:37` Location at `0x56dfbf8`. The #115 Location is independently read at `0x64767a8` with line 123 and column 37. An optional authenticated #94 check validates its selected JSON insertion call `0x363f1e9 -> 0x339e370` and zero-result continuation `0x363f120`. It also compares the #94 writer bytes at `0x4c648b1` with the #115 bytes at `0x4d93401`: the 20 unmasked bytes are identical and implement the two selected omission predicates. The earlier release's call and the new post-collection sorting route are different selected observations; this does not establish release-wide compatibility, equivalent functions or identical state layouts.

### Inferences and unresolved links

The field literal and surrounding typed descriptor records support the descriptive scheduled-cancel and map names; exact source types remain inferred. Both input paths and both later consumers are statically connected only along the recorded conditions and prior boundary results. Dynamic linker interposition, ordering for the large-sort delegate, exact accepted user-key syntax and time grammar, error objects, iterator mutation, complete serialized bytes, root preimage and final digest are unresolved. Snapshot omission predicates do not prove that the root visitor omits those fields. No complete begin/action/end-block behavior is claimed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags, two-build comparison, target-to-reconstruction raw or normalized comparison, helper closure, dynamic bindings, relocation/vtable/data closure and whole-ELF comparison are not yet measured. No normalization masks are used for selected windows, and no target bytes are transplanted into an implementation. Synthetic tables model checked guards and are not differential tests against a running target.

## Results and limitations

`summary.json` records 25 selected FDEs, 147 byte windows, 67 transfers, 66 branch witnesses, 15 relative relocations, 2 imports and 10 literals; these are selections, not coverage rates. The focused suite passed 20 tests with no skips, including corrupted hashes before output, changed bytes in every selected window, changed direct targets, real relocation corruption even with an adjusted digest, duplicate or malformed FDE and relocation records, NOBITS, ambiguous and out-of-range mappings, damaged dispatch entries, every byte of the 20-byte key comparison, field-presence controls, copy-range bounds, clone representation and overflow, and tree-length boundaries. Two independent regenerations with distinct hash seeds and time zones matched byte for byte, with binutils absent from `PATH`; artifact verification and the catalogue check also passed.

No `abci` component gate is requested. The complete first component task, full action dispatch, every failure or unwind, live state identity, all root inputs, whole snapshot, final digest and an independently built node remain open. Next question: follow the selected collection-copy and clone iterator helpers through both compact and tree representations, and check the reader-to-loader and block-task identity under all relevant intervening calls.
