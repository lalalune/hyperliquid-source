# RE-010: nested validator dispatch and state-removal path

The node #115 bytes expose an `unregister` niche encoding and a matching three-arm state routine whose other arm has two early return conditions, several conditional removals, and a further keyed update that a reconstruction must account for separately.

- Component ID: `action-dispatch` (`RE-010`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as an unlicensed investigation lead, with no code copied.
- Claim status: selected byte observations; subtype-to-state association is an inference; the complete parent-to-state handoff remains unresolved in this packet.
- Scope included and excluded: one nested serialization/clone path, one state routine's nonzero/non-one branch, its selected removal helpers, and a follow-up keyed update. This does not analyze the already-owned top-level dispatchers or wrapper, all subtypes, all helper bodies, all exception paths, or runtime behavior.

## Reproduce

Run from the repository root after placing the new files in their recorded relative paths. The target ELF is `artifacts/node/115/hl-node`. The generator checks its full SHA-256 before extracting anything, imports the repository ELF and FDE readers, and never executes the target or invokes an external program. It was checked with CPython 3.12.3 on Linux x86-64; the generator and tests require only the standard library and the two existing readers. GNU objdump 2.42 was used for human instruction inspection only, and none of its output is parsed by the tool or tests.

`FIRST-OUTPUT` and `SECOND-OUTPUT` below are distinct disposable, initially empty relative directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re010_cvalidator_unregister_115.py --out FIRST-OUTPUT
PYTHONHASHSEED=97 TZ=Pacific/Honolulu python3 tools/re010_cvalidator_unregister_115.py --out SECOND-OUTPUT
diff -r FIRST-OUTPUT SECOND-OUTPUT
for f in FIRST-OUTPUT/*; do
  cmp "$f" "research/work-items/RE-010-cvalidator-unregister-115/${f##*/}"
done
(cd research/work-items/RE-010-cvalidator-unregister-115 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_re010_cvalidator_unregister_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

`MANIFEST.sha256` records the hashes of this README and all generated files. The selected-window, body, relocation, branch and operand output is raw bytes or fixed-pattern decoding; it is not produced by parsing binutils text. The tests have no binary-missing skip and can be run with a `PATH` that contains Python but no binutils. The eight decision vectors, seven niche vectors, 27 compact-container vectors, and 18 representation-transition vectors are explicitly synthetic models of selected instructions, not target executions.

## Evidence

All code and data coordinates below are linked ELF virtual addresses (VAs), not runtime relocated addresses. `functions.tsv` also gives file offsets, FDE and CIE coordinates, LSDA when present, and a SHA-256 of each complete FDE range; `bodies.tsv` preserves those exact ranges. `windows.tsv` has 94 selected instruction-aligned byte ranges; `branches.tsv` and `calls.tsv` decode 81 selected branch sites and 32 direct calls. Their lists are selected slices, not counts of all possible branches, calls, or node functions. `operands.tsv` decodes 43 fixed-prefix immediate operands and `derived-operands.tsv` computes two record strides from checked instruction patterns. `relocations.tsv` records nine selected RELA entries. No match denominator is inferred.

| Selected role | FDE start | FDE end, exclusive | What is established here |
|---|---:|---:|---|
| Outer serializer | `0x53b2db0` | `0x53b5295` | Internal tag `0x3b` selects the `0x53b455b` arm. |
| Nested field adapter | `0x526e9f0` | `0x526ea47` | The first field calls the nested field serializer. |
| Nested field serializer | `0x5382f60` | `0x5383330` | Its other arm supplies the `unregister` literal. |
| Named nested serializer | `0x5382a50` | `0x5382f58` | The three arms supply distinct names and ordinal arguments. |
| Outer clone | `0x565a210` | `0x565b437` | The same internal tag selects a call to the nested clone. |
| Nested clone | `0x5659f70` | `0x565a20f` | Its other arm stores the canonical niche word. |
| Variant visitor | `0x574d0f0` | `0x574e2ec` | The selected diagnostic identifies `VoteGlobalAction::CValidator`; two paths store tag `0x3b`. |
| State routine | `0x3c3d480` | `0x3c3f412` | A matching three-way selector and the selected state path. |
| State follow-up | `0x3c36ba0` | `0x3c374dd` | Selected keyed search, insert and update paths after removals. |
| Follow-up tree entry | `0x370bed0` | `0x370bfe5` | Empty-root allocation, key stores, count update, and failure calls. |
| Follow-up compact lookup | `0x455a9e0` | `0x455aba7` | Selected equal and missing return encodings for a 20-byte key. |
| Follow-up compact insert | `0x4548f00` | `0x4549009` | Index check, shifts, 56-byte record copy and count increment. |
| Follow-up tree insert | `0x370d5e0` | `0x370d72a` | Empty-root key/value stores, count update and failure calls. |

The FDEs and unwind index agree on these starts and ranges; the selected ranges are file-backed executable bytes. An FDE describes an unwind range and is not, by itself, a proof of a source-level function or all of its entries. In particular, `0x3c3d61d` is inside the FDE beginning at `0x3c3d480`, and is not an unwind-indexed start; the reference handler split does not establish a separate machine function there.

### Nested identity and selectors

At the outer serializer and outer clone, subtracting `0x14` from internal tag `0x3b` selects jump-table index `0x27`; the independently decoded signed relative entries select `0x53b455b` and `0x565a61c`, respectively. Adjacent table entries are included as negative neighbors in `outer-switch.tsv`; no complete jump-table length is asserted. The serializer supplies the type literal `VoteGlobalAction`, ordinal `0x27`, a one-byte variant literal `O`, and a field count of two. It passes the payload at offset `+0x8` through `0x526e9f0` to `0x5382f60`, with the first one-byte field literal `a`; it then passes the payload at `+0x70` to a separate helper with field literal `c`. The visitor's selected diagnostic resolves through a `R_X86_64_RELATIVE` relocation to the literal `struct variant VoteGlobalAction::CValidator with 2 elements`. The visitor's entry selects a sequence route for content tag `0x14`; its empty-sequence route calls an error helper and stores marker `0x86`. This is a bounded visitor observation, not a complete malformed-input specification. `O`, `a`, and `c` are the literal arguments seen in this serializer specialization; no claim about every wire format follows.

For a 64-bit word `w`, the three inspected selector sequences calculate `n = (w + 0x8000000000000001) mod 2^64` when the sign bit is set, and zero otherwise. The named serializer supplies the type literal `CValidatorAction` and the following variant arguments; the state routine tests the same expression:

| `n` | Named serializer argument | Selected state-routine destination |
|---:|---|---|
| `0` | ordinal `0`, `register` | `0x3c3d5ce` |
| `1` | ordinal `1`, `changeProfile` | fall through at `0x3c3d4ed` |
| other | ordinal `2`, `unregister` | `0x3c3d61d` |

The nested clone stores `0x8000000000000001` on its other branch, giving `n = 2`. Higher negative words also take the observed other branch, but this does not establish that malformed words can enter through a real parser. The following human-readable excerpt shows the two selected state transfers and first early return; the corresponding raw bytes and offsets are generated in the evidence tables:

```text
0x3c3d4dd  0f84eb000000    je  0x3c3d5ce
0x3c3d4e7  0f8530010000    jne 0x3c3d61d
0x3c3dadc  6641c704244401  store 16-bit 0x144 to the result
```

### Selected other-arm state path

The observations below assume the selected routines return normally; offsets are relative to the state argument saved at function entry, and keys are compared using 20 bytes. The state routine's early global hook and cleanup paths are preserved in the FDE bytes, but are not fully modeled.

| Order | Selected condition / operation | Observation and branch consequence |
|---:|---|---|
| 1 | Look up the key in the collection at `state+0x110`. | Its sentinel `0x8000000000000000` selects a tree route; otherwise a compact lookup uses 64-byte records. If the found value pointer's `+0x20` word is nonzero, `0x3c3dadc` stores result word `0x144` and returns before the later selected removals. A missing entry or zero word proceeds. |
| 2 | Look up the same key at `state+0xd0`. | Tree and compact routes are separate; the compact lookup uses 112-byte records. A missing or out-of-range result reaches the store of `0x95` at `0x3c3dd1e`. The result object also receives other bytes; their meaning is unresolved. |
| 3 | With an initially found second entry, call the shared cleanup boundary at `0x3c3def8`. | Then copy 16 bytes from the found value pointer at `+0x3c` and four more at `+0x4c`; call `0x3ce5780` with the original key and the collection at `state+0x10`. This helper can find and remove a key, or find nothing. |
| 4 | Search `state+0xd0` again. | A tree match calls external boundary `0x3712d20`; a compact match calls `0x4562050`. A second miss can bypass the removal, so the earlier lookup does not prove this later removal always succeeds. |
| 5 | Search/remove the key at `state+0x288`. | The tree route calls `0x3903310`; the compact route calls `0x4555050`, and on its found route calls `0x4562190`, using 48-byte records. A compact miss skips that call. |
| 6 | Call `0x3c36ba0` with the original key and the copied 20-byte field. | On normal return, `0x3c3e788` writes `0x1a2`; the caller does not test a returned status from this call at that site. |

The state routine checks the representation sentinel and count below `0x20` around both `state+0xd0` and `state+0x288`, with subsequent collection replacement stores. This supports a representation-change inference; it does not establish the meaning of either collection. The named profile and index roles in filenames are analysis labels, not recovered source types.

The selected compact removal helpers check `index >= length` before changing their container. Otherwise their code computes `tail = length - index - 1`, chooses the prefix if `tail >= index` (including a tie), and chooses the suffix otherwise. On the prefix route it advances the circular start by one; both in-range routes decrement length after a shift call. The `compact-vectors.tsv` model assumes `capacity > 0`, `start < capacity`, and `length <= capacity`; it does not establish behavior for corrupted containers or model every byte copied. The 112-byte and 48-byte paths call distinct shift FDEs, both with selected indirect sites whose relocation identifies `memmove`; the tree comparisons use a relocation identifying `memcmp`.

### Follow-up map work

The `0x3c36ba0` routine takes the copied 20-byte field as a second key. It searches a tree rooted at `state+0x180` and calls `0x370bed0` when the search misses. In that helper's empty-root route, the code requests `0xe8` bytes through the selected indirect slot, installs the resulting pointer in the root, copies the 20-byte key into the node, and increments the collection count. A null allocation reaches the separate `0x370bfbc` call boundary; a node count at least `0xb` reaches the `0x370bfcc` boundary. The nonempty-root route delegates to `0x3506430`, whose body is not analyzed here. This supports insertion on the shown empty-root route without assuming the other helper's semantics.

The follow-up then looks up the same key in the collection at `state+0x1e8`: the compact route calls `0x455a9e0`, and an absent-entry route can call `0x4548f00`; the tree route can call `0x370d5e0`. The selected found-entry path stores a qword and the original 20-byte key into the existing value at `0x3c373a2` through `0x3c373bd`. The qword is chosen earlier from the collection at `state+0x48`, or set to zero on the selected empty route. The compact records use a 56-byte stride. A compact-found index outside the count reaches `0x3c37474`, a bounds-failure path, rather than the normal update. An existing-entry case and new-entry case therefore cannot be represented as only two unconditional map deletions.

| Selected follow-up operation | Success or update evidence | Boundary and failure evidence |
|---|---|---|
| Compact lookup | `0x455a9e0` compares 20-byte keys; a selected equal route clears `eax` at `0x455ab05`, while a selected missing route sets it to one at `0x455aafb`; the index is returned in `rdx`. | An empty collection also reaches the one-valued result; only selected branches are enumerated. |
| Compact insert | `0x4548f00` uses a 56-byte record, increments the count at `0x4548fc2`, and copies the input record. It chooses a head or tail shift from the insertion position and remaining length. | An index greater than the current length takes `0x4548ff0`; equality is allowed. At equal length and capacity, a separate indirect helper is called before insertion. |
| Tree insert | On an empty root, `0x370d5e0` requests `0x248` bytes, installs the root, stores a 20-byte key and 32-byte value, and increments the count. | Null allocation takes `0x370d701`; a node count at least `0xb` takes `0x370d711`. The nonempty-root call is an external boundary. |

The 32-byte tree value includes the qword and original key prepared by the caller; its remaining bytes are not assigned a source type. Both selected fresh-root routes initialize the node count to zero before their `0xb` checks, so the recorded full-node branches are not asserted reachable from those initializations under valid memory. Neither the compact insertion's growth helper nor the tree insertion's nonempty-root helper is fully analyzed.

The follow-up also checks a below-`0x20` small-tree condition and, on a compact missing-key route, a count-at-least-`0x40` condition before collection replacement or conversion. `transition-vectors.tsv` records synthetic cases on both sides of these boundaries, including found-key and sentinel controls. Which business relation this map represents and the complete behavior of its callees remain unresolved.

### Observations versus inference and prior material

The named serializer, clone, visitor, state selector, state offsets, relocation, and selected direct transfers are observations of #115 bytes. Associating the state routine's other arm with the named `unregister` subtype is an inference from the matching selector arithmetic and representation, the selected surrounding dataflow, and the reference lead. An indirect call through the slot whose relocation targets the state routine occurs in a previously surveyed wrapper, but that wrapper is already owned and is excluded here; the full parent-to-state handoff is not regenerated by this packet. Neither the matching arithmetic nor the slot alone proves the complete source-level call path. The labels `stake`, `profile`, `index`, `tree`, and `compact` are descriptive analysis names, not asserted original Rust declarations.

For provenance only, historical #94 research used node SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` and reported a top-level `CValidator` case at `0x2759b0b` and a first handler at `0x2768ff0`. Those coordinates are not #115 coordinates, are not input to this tool, and were not revalidated from #94 bytes in this packet. The `VoteGlobalAction` internal tag above and the historical top-level case occupy different coordinate systems; no equality is implied.

## Implementation and comparison

Independent implementation: not yet implemented. Cargo dependency graph, compiler/linker flags, binary comparisons, normalization masks, relocation or whole-ELF closure, and two-build comparison: not yet measured. The fixed-site extraction and synthetic models are evidence for a future implementation, not a reconstructed node or target-equivalence test. The external cleanup, nonempty-tree helpers, allocator, serializer, and shift call boundaries require separate closure analysis. No live fixtures, node process, network, keys, or chain state were used.

## Results and limitations

The generator emits 16 deterministic files: 22 selected FDE ranges, 94 byte windows, 81 branches, 32 direct calls, 43 fixed immediates, two derived operands, nine relocation records, six outer table entries, seven identity records, three name records, seven synthetic niche vectors, eight synthetic decision vectors, 27 synthetic compact vectors, and 18 synthetic transition vectors. These are selected-record denominators only. The focused unittest suite has 23 tests, including damaged hash, branch, byte prefix, relocation, address-range and container-invariant controls; none execute the target. No component progress gate is requested.

The parent dispatch-to-state edge, caller authorization, representation invariants, exact result variants, error precedence beyond these selected branches, all unwind/exception side effects, complete helper closure, and state transaction semantics remain open. The next question is to validate the already-owned wrapper's exact payload and key handoff to `0x3c3d480` without duplicating that prior function, then identify the copied 20-byte field and `state+0x1e8` map using independent #115 evidence.
