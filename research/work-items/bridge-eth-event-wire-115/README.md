# bridge: reconstruct the node #115 wire form of EthEventId and of the two deposit vote actions

This packet lets a reconstruction build the `EthEventId` key (five fields `b`, `t`, `e`, `i`, `h` in 64 bytes, `e` a six-name event type, `h` a `0x` hex string) and the two deposit vote actions (flat `VoteEthDepositAction` and nested `l1ValidatorVoteBridgeDeposit`) for node #115 from its own bytes: nine entry functions of three compiled families and thirteen further copies run in an interpreter against an independent rule list that predicts every output byte and every error text, with 11,455 cases matching and 34 of 34 negative controls caught.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; first task "Map message hashes, nonce lifecycle and validator signing threshold"; only the identity and wire form of a deposit vote are claimed here)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; the reference tree was not consulted (no clone in the work area), nothing copied
- Claim status: observation for bytes, entry addresses, output bytes, error text and rodata text; inference for the meaning of each field and for which vote arm each action feeds; unresolved items are under limits
- Scope included and excluded: included are the 9 entry functions in `path.tsv` and 13 compiled copies in `copies.tsv`. Excluded are the `Action` enum dispatchers that call them, the msgpack reader that builds a `Content` value, the standalone `EthEventId` and nested-action readers (see Limits), what a vote does with the key, and the validator set update actions that also carry this key.

Provenance of the method: the same rule list and interpreter were written for node #94 in an earlier packet that is not part of this repository. Nothing from #94 is credited here. Every address, import slot, allocator entry and text address in this packet was found again in the #115 bytes (below), and each claim here is backed by the #115 run.

## Reproduce

```
python3 tools/bridge_eth_event_wire_115.py --out research/work-items/bridge-eth-event-wire-115
python3 -m unittest tests.test_bridge_eth_event_wire_115
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is never executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function from its entry, `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 2 minutes and about 0.75 GB of resident memory; cases are built one at a time and only counts and rows are kept.

## Evidence

Addresses are virtual addresses. `function-rows.tsv` has every instruction row the cases reached; `key-rows.tsv` binds the rows quoted below, so a moved row fails the run.

### Entry functions (how they were found in #115)

| Name | Entry | Bytes | Copies |
|---|---|---|---|
| `flat_msgpack_a` | `0x290ce10` | 811 | `0x46cc580`, `0x5925bb0` |
| `nested_msgpack_a` | `0x291bde0` | 949 | `0x421cf30`, `0x592e950` |
| `flat_msgpack_b` | `0x290c4b0` | 517 | `0x46cc8b0`, `0x5925520` |
| `nested_msgpack_b` | `0x291b860` | 567 | `0x592e710` |
| `action_msgpack_b` | `0x46ccda0` | 405 | none found |
| `action_json` | `0x290c6c0` | 804 | `0x5925730` |
| `flat_json` | `0x290cb40` | 711 | `0x46cc1a0`, `0x5926010` |
| `action_from_content_rmp` | `0x2011090` | 4595 | `0x39efd10`, `0x572ce20` |
| `action_from_content_json` | `0x20baff0` | 3441 | `0x3a85fe0` |

Method: the `ethId` and `VoteEthDepositAction` texts (rodata `0x5e68e0`, `0x5e68ec` and five more pool copies) were followed by RIP-relative `lea` references to the functions that use them, plus a scan for the msgpack head byte computation `shl 4; or 0x82..0x85` of the map-or-array flag. Each candidate was run against the rule list and kept only when every output byte matched on the default fixture; the readers were then split into rmp and JSON flavour by running all 65 action cases (the wrong flavour fails 42 of them on the error type).

### The key

| Field | On the wire | Bound by |
|---|---|---|
| `b` | unsigned integer | head row of each writer in `key-rows.tsv` |
| `t` | unsigned integer | wire samples |
| `e` | name string, six names in index order | `events.tsv` (three pools of `(pointer, length)` rows, RELATIVE relocations) |
| `i` | unsigned integer | wire samples |
| `h` | `0x` + 64 lower hex digits | wire samples |

The head byte is `0x85` or `0x95` for the key, `0x84` or `0x94` for the flat form and `0x82` or `0x92` for the nested form (high bit pattern from the named/compact flag). Integers take the smallest msgpack width. The `b` writers pass the field count in `edx` to a map-length helper instead of computing the head byte; `key-rows.tsv` binds that row for them.

```
flat    {type: "VoteEthDepositAction", user, usd, ethId: {b, t, e, i, h}}
nested  {type: "l1ValidatorVoteBridgeDeposit", action: {user, usd, ethId}}
```

### Layout of the fixture

The action is `usd` at `+0`, the key at `+8` (`b` `+0`, `t` `+8`, `i` `+0x10`, hash `+0x18`, event byte `+0x38`) and `user` at `+0x48`. The same offsets drive all nine entries in #115 as in the earlier #94 packet.

### Input rules

The two readers take a buffered serde `Content` value (tag `0x14` sequence, `0x15` map, `0x13` newtype). They differ in the error type: the JSON flavour boxes a `serde_json` error, the rmp flavour returns an inline error. Unit prints as `null` in the first and `unit value` in the second.

| Rule | Example case |
|---|---|
| the action refuses an unknown key; `EthEventId` ignores one | `extra_key` cases |
| sequence form works at each level; too short or too long gives the length error | `seq_*` |
| a duplicate field is refused before its value is read | `dup_*` |
| a key may be text, bytes, or a `u8` or `u64` index | `int_keys`, `bytes_keys` |
| `b`, `t`, `i`, `usd` take any non-negative integer width, no text | `usd_*`, `b_*` |
| `usd` takes one newtype layer, `user` any number | `usd_newtype_newtype`, `user_newtype_newtype` |
| hex: optional lower-case `0x`, either digit case, length tested before digits; raw bytes of exact size pass | `h_*`, `user_*` |
| a bad hex digit is named by its byte as a Latin-1 character | `h_bad_nonascii` |

### Allocator and imports in #115

Unlike the earlier release, the compiled code reaches the allocator through RELATIVE-relocated slots that hold direct function addresses: `0x64df480` holds `0x6355830` (allocate), `0x64df4a0` holds `0x635de30` (free with size), the realloc entry is `0x635a7a0`, and `0x64df4c0`, `0x64df770` hold the two diverging allocation-error stubs `0x1680cab`, `0x1680bd0`. `memcpy`, `memmove`, `memcmp`, `bcmp`, `malloc`, `free`, `realloc`, `abort` and `_Unwind_Resume` slots are read from `.dynsym` names through GLOB_DAT and JUMP_SLOT relocations. The interpreter models these as fixtures and checks that every free carries the size that was allocated.

## Implementation and comparison

`tools/bridge_eth_event_wire_115.py` holds a decoder for the x86-64 subset the nine functions and their callees use, a machine with checked memory, and a rule list `spec_run`, written apart from the machine, that predicts each serializer's bytes and each reader's decoded fields or error text. `negative_controls` runs 34 deliberately wrong checks: 7 head-byte or length immediates flipped in the real code, 4 Content tag compares flipped in the readers, 7 entries run as the wrong writer, 14 wrong rule lists (integer width edges, string width, JSON indent, field order, hex case, unknown-key refusal, newtype unwrap, error text, and others), and 6 bad inputs (wrong digest, non-start address, address outside the file, truncated RELA, changed event name byte, changed text byte). A control that is not caught stops the run.

## Results and limitations

- 9 entry functions, 2373 reached instruction rows, 13 copies. 1510 named cases, 9000 generated cases and 945 copy cases (11,455 in all, `measure.json`): 0 mismatches. Every allocation is checked: an accepted input leaves nothing live, an error leaves only the error, and each free carries the right size.
- 34 of 34 negative controls caught (`negatives.tsv`).
- 510 byte edits on reached rows (every second one): 393 killed, 117 survived (`mutations.tsv`). A survivor has a class label only and is not proved equal; many surviving branches are writer capacity tests, where growing early can write the same bytes. These edits are reported apart from the negative controls and are not counted in them.
- 1636 bytes of the 9 bodies are not reached: landing pads, allocation failure and rows for writer errors. There is no list of those rows, because the tool decodes only from reached rows.
- The rule list was written for the earlier release and matched on the first #115 run without change, so a match shows the rules and layouts hold in #115; it is not an independent prediction made from #115 alone.
- The `Content` value is built by the fixture from the serde tag layout, not by the real msgpack reader. Float and char `Content` values are not tested.
- Not found in #115: standalone `EthEventId` writers and readers, a JSON nested writer, an `action_msgpack_a` and the nested-action readers. Their callers inline or share code, or the candidates I probed had a different signature (the `0x291bb90`, `0x592e4c0`, `0x421d0c0` family takes a visitor argument). They remain unresolved, not absent.
- Field meanings are inference: `b` as a block number, `h` as a transaction hash, `i` as a log index; `t` is not established. That the flat form feeds one vote arm and the nested form another is inference from the names; no dispatch is run here.
- Searched other open PRs by address and by the names EthEventId and bridge: no overlap found; open #4333 concerns a selected preimage and digest, not these functions. Addresses `0x290ce10`.. appear in existing evidence only as listing rows (callers and dispatch arms) in `RE-001-*` and `RE-010-action-serialize-tag-dispatch-115`.

Next question: the visitor-style readers of the nested action (`0x291bb90`, `0x592e4c0`, `0x421d0c0`) and the standalone key readers, then the function that builds these keys from Ethereum logs.
