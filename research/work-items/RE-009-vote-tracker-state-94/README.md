# RE-009: vote tracker snapshot codec

Node #94's `vtg` snapshot codec has a unit-keyed `i` collection and shares one `VoteGlobalAction` writer between the `qst` payload and `vts` keys, enabling a reconstruction to preserve their nesting and duplicate-key decisions.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23` was a search lead only.
- Claim status: observed bytes and bounded static control-flow inferences; no native execution or equivalence claim.
- Scope included and excluded: the selected `vtg` MessagePack-shaped writer and reader, their `i` collection, one nonempty pair, and the `qst`/`vts` writer convergence. The previously studied parent bodies are context only. Complete `VoteGlobalAction` payloads, nested `vks` and `hvs` values, JSON, alternate serializer modes, all malformed inputs, other node releases, chain state and on-disk reachability are excluded.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3, its standard library, and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/vote_tracker_state.py --out work/vote-tracker-state-94
python3 -m unittest tests.test_vote_tracker_state
for f in action-dispatch.tsv branches.tsv edges.tsv functions.tsv materialize-guard.tsv records.json; do
  cmp "work/vote-tracker-state-94/$f" "research/work-items/RE-009-vote-tracker-state-94/$f"
done
```

The generator checks the full target SHA-256 before parsing. It reads ELF sections, the unwind index, CIE/FDE records, selected instruction and data bytes, signed relative tables and dynamic relocations; it makes no external calls and does not execute the node. It rejects ambiguous or non-file-backed address mappings, including `SHT_NOBITS`. GNU objdump 2.42 was used only for human inspection; no generated file or test parses its output. Two runs with `PYTHONHASHSEED=7` and `99`, `TZ=UTC` and `Pacific/Honolulu`, and a PATH containing Python but no binutils produced byte-identical files. `MANIFEST.sha256` gives the retained file hashes.

## Evidence

All addresses are unrelocated ELF virtual addresses; the records also include file offsets, unmasked bytes and exclusive FDE ends. The 29 selected FDE ranges are listed in `functions.tsv`. The 71 selected direct calls and jumps are in `edges.tsv`, the 148 selected conditional branches are in `branches.tsv`, and 164 byte windows, 27 literal references, eight short relative-table spans, two dynamic relocations, and the bounded action table are in `records.json`. These are selected records, not a census. An FDE is an unwind-described extent; it does not establish the absence of cold code, a complete function boundary, or component ownership.

### Entry and tracker fields

The prior state analysis identifies the containing serialization context; only its local call sites are used here. At `0x275b413`, the caller forms `r14 + 0x3510` and calls the new field writer at `0x275b420`. That wrapper references `vtg` at `0x27b2a91` and tail-jumps to `0x2326ba0`. The separate reader context reaches a duplicate-`vtg` diagnostic at `0x16de54b`; its other branch passes the 11-byte string `VoteTracker` and calls `0x169d700` at `0x16dad02`. This ties the two selected child paths to the same field name without claiming a new analysis of the parent bodies. The earlier context is documented in `research/work-items/staking-vote-quorum-94/README.md` and `research/work-items/staking-cstaking-state-wire-94/README.md`.

For serializer mode byte `+0xb` restricted to 0 or 1, the tracker writer uses the already studied header and string helpers in `research/work-items/RE-009-evm-state-wire-94/README.md`:

| Order | Named mode 1 | Positional mode 0 | Selected value operation |
| --- | --- | --- | --- |
| header | map of 3 | array of 3 | header calls at `0x2326bd2` and `0x2326c01` |
| first | key `name` | omit key | pass words at input `+0x8` and `+0x10` to the string helper at `0x2326c46` |
| second | key `hsc` | omit key | call the array-header helper with length zero at `0x2326c7a` |
| third | key `i` | omit key | pass input `+0x18` to `0x25eab80` at `0x2326cb7` |

Header, key and value checks branch to error propagation before subsequent fields. The wrapper also checks its outer key write. Bytes other than 0 and 1 at the serializer mode byte have different tests in this body and are not modeled as either named or positional mode.

The map reader's key comparisons return selectors 0, 1, 2 and 3 for `name`, `hsc`, `i` and other decoded byte strings, respectively. The first table at `0x286384` selects the three child paths; after a successful `i`, the second table at `0x286398` routes a second `i` to the duplicate-field diagnostic. `name` and `hsc` have explicit seen checks. The unknown-key path calls the helper at `0x169de14` and continues only on its success tag; the helper itself is not analyzed here. At completion, the selected missing-field checks name `name` and `i`. The omission behavior of `hsc` is not fully characterized here.

### `i` collection, row, and error branches

The adapter calls `0x256a2c0` to materialize 16-byte pointer pairs, then `0x1e33970` writes an array header and iterates at stride `0x10`. In the selected streaming state, the pair writer at `0x1de7cb0` writes a two-element array header, calls `0x1e100c0` for the first element, then calls the row writer at `0x2321230`. The first child stores byte `0xc0` at `0x1e101a6` when its buffer has space. Other buffering and serializer-option paths exist; the precise claim about that direct byte is limited to this streaming state.

The row writer names three fields, `arq`, `qst`, `vts`, in that order. It loads `arq` from input `+0x108`, combines it with `0xc2`, and calls a marker helper. For `qst`, a 32-bit tag equal to `0x74` selects the string `N`; otherwise the selected branch writes a one-entry map with key `Q` and calls `0x236b260`. `vts` is passed from input `+0xf0` to `0x25e8ca0`. The corresponding row reader has a field-name switch at `0x2d5344`; its field diagnostic strings are `arq`, `qst`, and `vts`. Its relocated descriptor at `0x56880a8` references the text `struct UniqueKeyState with 3 elements`. That text is a binary diagnostic, not proof of an original Rust declaration.

The `qst` reader `0x1684b00` adds compatibility decisions for the same row. Its decoded-name classifier `0x2301760` accepts exactly one-byte `N` and `Q`, returning different selector bytes. A bare `N` reaches the `0x74` sentinel. A bare `Q` calls the error builder at `0x1705920`; its error result is converted to the reader's `0x75` error tag. On the selected fixed-map path, only one entry reaches `0x2302f30`; counts zero or greater than one reach the bad-count result. A one-entry `N` map accepts the `0xc0` nil marker, while a `Q` map delegates its value to `0x1687210`. Missing input, other names, non-nil `N` values and a failed action child have separate error routes. These are conditional control-flow observations, not complete encoded fixtures or an exhaustive marker grammar.

The selected reader for `i` recognizes fixed-map and fixed-array headers. Under the uncached-marker path and after the depth checks, `0x80` selects a zero-count map visitor and `0x90` a zero-count sequence visitor; both visitors produce their success tag. A nonempty map reads a key with `0x1968910` and then the row with `0x17c2a60`. A nonempty sequence uses the pair reader `0x183a210`, which invokes the same key and row readers. The following decisions apply after the preceding child operations succeed; malformed children can fail earlier.

| Selected condition | Taken destination | Observation |
| --- | --- | --- |
| `i` map count 0 / sequence count 0 | `0x263f7ef` / `0x266497d` | each visitor sets success tag 9 |
| pair count 0 | `0x183a969` | missing first element route |
| pair count 1 after a successful key | `0x183a9cd` | missing second element route |
| pair count 2 after both children succeed | fall through from `0x183a8fb` | pair result proceeds to the normal join |
| pair count greater than 2 after both children succeed | `0x183a91a` | extra-element error result |
| key reader failure / row reader failure in map | `0x263f816` / `0x263f839` | propagate child error |
| existing map or sequence slot, old row tag unequal to `0x75` | `0x263f86f` / `0x26649c1` | both construct the bytes `duplicate key` |
| zero depth before or immediately after decrement | `0x18cb130`, `0x18cb13d`, or `0x18cb0c5` | selected container depth failure routes |

For an uncached key marker `0xc0`, the relative dispatch at `0x363394` reaches the indirect call at `0x1968946`; its `R_X86_64_RELATIVE` slot resolves statically to `0x2ea2950`, whose `0xc0` slot reaches the tag-9 return at `0x2ea2975`. The map visitors select an existing entry without comparing key bytes and replace/check its row. These observations support the inference that this instantiation has a unit-like key and at most one successfully inserted entry. In particular, a second successfully decoded unit key and row reaches the duplicate route under the normal tree insertion invariant. No claim is made that every encoding of a key is accepted or that a malformed second row reaches the duplicate check first.

The separate `hsc` reader reaches the same success tag for uncached `0xc0` and empty fixed array `0x90` on the traced paths. A missing input byte takes `0x168ee12`. These are bounded marker decisions, not a complete acceptance grammar.

### Nested `vts` and allocation-size guard

The `vts` writer follows `0x25e8ca0` to `0x1e2a840`, which emits a collection header and visits 16-byte pointer pairs. In the selected streaming route, `0x1dd5ac0` calls `0x236b260` for a key and `0x231d2c0` for its value, checking each return before continuing. The value writer has two named fields, `vks` and `hvs`, with the latter passed from value `+0x18`; their child codecs remain outside this packet. The same `0x236b260` is reached by the row's `Q` path. It passes the binary string `VoteGlobalAction` to selected variant writers.

The action writer computes a table index from a loaded 64-bit discriminant using threshold `0x12` and fallback index `0x4e`. `action-dispatch.tsv` records the 79 entries in that selected table span: all 79 targets are distinct and inside its FDE. Inputs below `0x12` select the fallback slot, while values `0x12` through `0x60` address slots 0 through `0x4e`. The table is not a census of valid or constructible variants; the program does not supply an upper-bound check at this point, and behavior for other in-memory values is not modeled. The row's `0x74` sentinel is handled before the `Q` call.

At `0x256a2c8`, the `i` materializer obtains a count, shifts it left four bits, checks the original high four bits, and compares the shifted byte size with `0x7ffffffffffffff8`. The selected unsigned guard reaches the indirect call at `0x256a2f6` for counts above `0x7ffffffffffffff`. `materialize-guard.tsv` contains arithmetic-model controls on both sides of this boundary and at 64-bit wraparound. This records the branch and its arguments; the indirect callee's effects are not established.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no build, binary comparison, runtime fixture, or execution of the captured node. No bytes or operands were masked. The 22 focused unittest methods include a wrong digest, FDE and body corruption, changed instruction and branch bytes, changed literal and table data, altered relocation type, invalid or `SHT_NOBITS` addresses, all single-bit substitutions of the three tracker field names, all 256 one-byte `qst` names and fixed-header marker values, pair-length boundaries, and allocation-guard boundaries. The classifier and arithmetic checks are static models of the selected branches, not target executions. The overlapping stores that construct `duplicate key` are modeled in store order, including a control for a byte overwritten by the later store.

## Results and limitations

The retained analysis contains 29 FDE-described ranges, 71 selected direct edges, 148 conditional branches, 164 fixed byte windows, 27 literal references, eight short table spans, two relocations and one 79-entry action-table span. The six generated evidence files reproduce byte for byte, and all 22 focused tests pass without skips. These denominators describe only the selected evidence; they are not function coverage, behavioral equivalence, or a reviewed full-scope milestone gate. The unselected serializer modes, inner action variants and values, full `hsc` omission behavior, nested `vks`/`hvs`, allocator behavior, cold paths, and actual persisted fixtures remain unresolved.

Next question: recover the `vks` and `hvs` child codecs and the matching nonempty `vts` reader, then compare complete fixtures in a separately authorized offline harness.
