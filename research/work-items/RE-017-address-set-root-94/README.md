# RE-017: address-set state loading, mutation gate and root input

Node #94's JSON and MessagePack readers use the same duplicate-collapsing insertion for the `disabled_precompiles` field, while a separate action-address gate recognizes exactly the twenty keys `0x0800` through `0x0813`; a matching materializer offset and low-lane root capture give a reconstruction a conditional path from this loaded set to hash input.

- Component ID: `abci`, RE-017; one address-set lifecycle within state loading and root inputs.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed inferred lead `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. No lead implementation was copied.
- Claim status: selected bytes, table entries, relocation records and destinations are observations; field identity, live-object continuity and lifecycle composition are inferences or conditions below.
- Scope included and excluded: thirteen newly selected FDE ranges, fixed JSON and MessagePack value-reader routes, their shared set insertion, one action-address gate, low/shared root-input writers, and separately marked prior-function boundary windows. Original RE-017 loader call sites and GOT slots are not reselected. Complete begin/action/end-block execution, every input grammar, allocator and balancing internals, node #115 and visor are excluded.

## Reproduce

Run from the repository root with CPython 3.12 and its standard library. The generator authenticates the entire input first, reads it as data, imports the repository's shared ELF and FDE modules, excludes SHT_NOBITS mappings, and invokes no external program. It writes only the requested directory; it does not execute the captured program or access a network. GNU objdump 2.42 was used only for bounded human inspection and is not used by the producer or tests.

```sh
python3 tools/artifacts.py verify
python3 tools/abci_address_set94.py --out research/work-items/RE-017-address-set-root-94
python3 -m unittest tests.test_abci_address_set94
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_address_set94.py --out <tmp-dir>/first
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_address_set94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/first research/work-items/RE-017-address-set-root-94
(cd research/work-items/RE-017-address-set-root-94 && sha256sum -c MANIFEST.sha256)
```

Replace `<tmp-dir>` with an empty writable directory. The generator creates `evidence.json`, `functions.tsv`, `windows.tsv`, `direct_edges.tsv`, `branches.tsv`, `relocations.tsv`, `rip_references.tsv`, `gate_cases.tsv`, and `summary.json`; the manifest covers all of them and this README. The raw windows are unmasked. The generator decodes only fixed, checked instruction forms; it is not a general disassembler.

## Evidence

All addresses are unrelocated ELF virtual addresses. `functions.tsv` separately records file offsets, exclusive FDE ends, CIE/FDE and LSDA addresses, and complete-range SHA-256 values. Each selected start has a matching `.eh_frame_hdr` record and `.eh_frame` FDE. An unwind range is not by itself a source-function boundary, a complete CFG, or an ownership claim for other code in the section. `windows.tsv` labels the fifteen connecting windows in previously studied extents as `prior-boundary`; the corresponding whole functions are not selected. The branches and edges are selected instruction starts, not a whole-program census.

### Entry from prior work

The [state-link packet](../RE-017-abci-state-link-94/README.md) associates the loader with a `state.rs` Location; [RE-019](../RE-019-rmp-json-loader-94/README.md) records its JSON and MessagePack arms. The earlier JSON Exchange-dispatch packet, PR #1369, identifies field tag 45 and its `disabled_precompiles` duplicate guard; it does not examine that field's value reader. Its field arm leads through the newly selected colon/child boundary at `0x2fe808c` to `0x308a550`. In the separate MessagePack field visitor, the duplicate branch supplies the same 20-byte literal and the new call at `0x2abb7da` reaches `0x2bfdab0`. This packet does not re-own either previously studied visitor or claim a complete format-to-file path for every decoding mode.

### Readers and insertion

| Selected extent | Observation from the selected path |
| --- | --- |
| `0x308a550` | JSON array entry and depth checks; the loop calls the sequence adapter, copies a 20-byte returned payload, and calls insertion. A child error drops the temporary set; a no-element result proceeds to container completion. |
| `0x3018f10` | Sequence adapter distinguishes `]`, comma, whitespace, a delegated value, and error exits. Its value path calls `0x3586f00`. |
| `0x3586f00`, `0x35c8330` | On a selected quoted-value path the adapter calls a separately relocated decoder with output width 20. Decoder return 3 copies 16 plus 4 output bytes; another result follows an error-construction path. Other value forms and the decoder's complete input language remain outside scope. |
| `0x2bfdab0` | On its selected fixed-array path, markers `0x90..0x9f` supply the low-nibble count. Each successful child has result byte 9 and supplies 20 bytes to the same insertion helper; a different child tag follows a failure path before that insertion. Other marker and predecoded-state routes are not fully interpreted. |
| `0x339ed10` | It compares 20 bytes through the relocation imported as `memcmp`. The equal branch returns byte 1 without reaching the set-count increment. A new entry reaches the increment of the word at set `+0x10`; the empty-root path allocates a `0xe8`-byte node. Nonempty structural insertion is delegated. |

Both inspected JSON and MessagePack loops continue after the insertion call without testing its return byte. Thus an equal key on these selected paths is not rejected merely because insertion returned 1 and does not increase that count. This does not prove that a failed parse publishes its temporary set or establish all malformed-input precedence.

Some failure and boundary branches are:

| Condition | Selected outcome |
| --- | --- |
| JSON field already present | The earlier field visitor's duplicate-field guard is taken before this value reader. |
| JSON input ends before an opening value, or its first nonspace byte is not `[` | Separate error-construction routes in the set reader; no insertion on those routes. |
| JSON nesting byte is zero, or becomes zero on decrement | Distinct failure paths before the selected element loop. |
| JSON element adapter reports an error | The local set is passed to cleanup before error propagation. |
| MessagePack nesting word is zero, or becomes zero on decrement | Distinct failure paths before the fixed-array loop. |
| MessagePack element tag differs from 9 | Transfer to the selected child-error path before insertion. |
| Insertion comparison returns equality | Return 1 on the existing-key path; do not reach the new-key count increment. |
| New root allocation returns zero | Transfer to the allocator-failure boundary. |

The JSON completion path tests its field-presence slot: when absent it writes zero for the root and count words; the middle word is not established by those two stores. On the selected present path it copies the 24-byte set representation from the child result to its result at `+0x1f10`. The selected prologue saves the output argument in `rbx`; a later window stores that value at stack `+0xc0`, and another reloads the same stack word into the base register for the result stores. This connection assumes the indicated stack word is not changed on the intervening path. The separate materializer boundary takes an input pointer plus `0x1f10` and copies those same 24 bytes to its output at `+0x3a30`. These are instruction and offset observations, not by themselves proof that an arbitrary visitor output is the later materializer's actual input.

### Action-address gate

The repository's existing [host instruction transcript](../RE-003-pr-integration-1265-1275/native/decoder-native/staking_core_writer-2355f40.txt) records the relevant host call and the subsequent two update-helper transfers. We cite that existing host as a boundary and do not regenerate its call site. The selected type-8 relocation at `0x5773df8` resolves the previously recorded gate slot to the newly examined `0x3b453d0`.

The gate starts a two-word iterator at zero. Its selected iterator yields indexes 0 through 29 and then sentinel 30; carry/overflow branches have separate failure calls. Relocated slots select `0x3b9d9b0` for the iterator and `0x3b45470` for 20-byte key construction. The latter's signed-offset table supplies 30 fixed arms, each yielding 16 bytes and an immediate four-byte suffix. `gate_cases.tsv` reconstructs every key from those instruction and data bytes. The gate compares all 20 bytes and, on a match, returns the result of `(index - 7) < 20` in byte arithmetic. A non-match reaches the sentinel and returns zero. Under the zero-initialized iterator and normal helper returns, the accepted set is precisely the 20 big-endian addresses whose final two bytes are `0800` through `0813`; the other ten enumerated addresses are not accepted. Table order is not numeric order: index 8 is `0813`.

This gate is separate from the field readers. The existing host transcript shows that a zero gate result reaches the common result path before either update call. A nonzero result tests the action byte and selects one of two previously recorded helper calls, passing a 20-byte value and the parent field at `+0x3a30`. The host observations are credited to that transcript; those older helper bodies are not owned or re-executed here. The decode-to-host live-object identity and actual action scheduling remain unresolved.

### Root-input writer

The earlier [app-hash builder](../RE-009-app-hash-builder-94/README.md) records low-lane job 28 capturing state `+0x3a30`; it leaves the captured field serializer open. New boundary calls from the low and shared closures reach `0x1e2aad0` and `0x4430b20`. Both load a root/depth/count triple and walk 20-byte entries, using the node's `+0xe6` length, parent and child fields. The low writer sends each selected key to `0x2806b00` or `0x2804dd0` according to its internal buffer state; the shared writer uses separate helper boundaries. Count, helper result, allocation failure, parent traversal and the counter-overflow exits are included in the selected branch table.

The low closure sets writer configuration `0x01000400`. On the direct, successful low-writer route with a count fitting 32 bits, the direct item helper sees a zero mode byte and passes the original 20 bytes to the previously studied binary writer. The buffered item's selected zero-mode route writes a `c4` marker and length byte `14` before copying the same 20 bytes. The prior array-header and binary-writer studies establish the corresponding direct header and copy decisions; their helper bodies are not selected here. Conditional on those helper contracts, ordinary returns, and a valid tree, a low-lane job-28 input is an array of 20-byte binary items in the observed traversal order. A source-language set type, sortedness after every delegated rebalance, the final digest, and the identity of the object at each stage are not proved.

### Inferences and unresolved links

The field literal, matching 20-byte keys, matching triple layout and selected offsets support interpreting the paths as views of the same disabled-address field. They do not establish that a particular parse result reaches the root builder unchanged, that a particular action runs, or that a digest changes. The existing byte windows establish local copies, not the entire intervening lifetime, scheduler or absence of writes. The action gate's accepted addresses do not establish what a precompile does.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, target execution, fixture run, binary equivalence, normalization masks, complete call-target/helper closure, vtable/data closure or whole-ELF comparison has been measured. Tests exercise static byte extraction, selected branch destinations and corruption controls, not execution of node #94. Dynamic `memcmp` binding is conditional on ordinary ELF symbol resolution; decoder, allocator, parser children, tree balancing and other serialization helpers remain boundaries.

## Results and limitations

`summary.json` records 13 selected FDE ranges totaling 11,611 bytes, 45 selected windows including 15 prior boundaries, 21 direct call sites, 86 selected branches, 4 RIP references, 5 relocations, 2 literal ranges and 30 gate-table cases of which 20 pass the derived index test. These are selected-record counts, not component coverage. The focused suite passes 16 tests without skips and includes wrong digest, missing/duplicate/mismatched FDE, NOBITS and ambiguous mappings, corrupted windows, all selected call and branch opcodes or displacements, invalid relocation records, changed gate-table bytes and invalid RIP references. Two independent generations with different hash seeds and time zones are compared byte for byte with binutils absent from `PATH`.

No ABCI progress gate is requested; the component remains 0/4. The full begin/action/end-block path, complete state-root preimage, scheduler and object identity, every value-grammar failure and every allocator/unwind edge remain open. Next question: establish the intervening loaded-object copies and the selected action-update helper semantics without re-owning earlier functions, then connect the resulting field to the low-lane builder under explicit aliasing and ordering conditions.
