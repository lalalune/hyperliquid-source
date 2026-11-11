# RE-001: node #115 settled outcome history text contract

The `soh` member of the spot clearinghouse snapshot was an opaque child of the
enclosing state exporter. This packet closes its successful structural text
projection, including the nested records, pair collections and wrapped queues.
It is preparatory static research for storage and outcome state, not a recovered
Rust implementation or a change to settlement policy.

- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: original ELF virtual addresses, exclusive function ends.
- Denominator: 29 complete FDE bodies, 18,097 bytes; not a whole-component
  denominator. All component acceptance gates remain false.

## Finding

The spot parent at `0x3bfd020` passes its member at offset `0x3b8` through
`0x3d2b350`, which emits the exact three-byte key `soh` and calls `0x3c03df0`.
The child emits five fields in this order. Each remains present for an empty
container. Serializer state checks do **not** mean that empty fields are omitted.

| Text key | Child offset | Successful output | Value implementation |
| --- | ---: | --- | --- |
| `sots` | `0x00` | Array of `[u64, settled outcome record]` pairs | `0x465cac0` |
| `sotq` | `0x48` | Array of `[u64, u64]` pairs | `0x465e1c0` |
| `sqts` | `0x90` | Array of `[u64, settled question record]` pairs | `0x4649b80` |
| `sqp` | `0xd8` | Array of u64 queue entries | `0x4658ca0` |
| `sqpq` | `0xf8` | Array of u64 queue entries | `0x3d2dc70` → `0x465a9e0` |

The attribution **SettledOutcomeHistory** is inferred from the `soh` parent
member, this five-key schema and the target's corresponding type-name metadata.
The addresses, field bytes, lengths, layouts and call targets above are direct
observations. Expanded meanings of the abbreviated keys are not needed for the
contract and are not invented here.

The first three collections are JSON arrays of pairs, **not JSON objects with
stringified keys**. Their dense storage order is retained; these writers neither
sort nor deduplicate it. `sots` advances 192 bytes per row, reads the key at
row+184 and passes the row start to `0x3c033f0`. `sotq` advances 24 bytes and
emits the qwords at row+8 and row+16, ignoring the first qword in this projection.
`sqts` advances 96 bytes, reads the key at row+88 and passes the row start to
`0x3c03c10`. Container construction and key-uniqueness rules remain outside this
successful writer contract.

Both queue writers use the descriptor's capacity, data pointer, head and length
at offsets 0, 8, 16 and 24. For valid descriptors, they serialize the contiguous
tail starting at the head, then any wrapped prefix from the data pointer. Elements
are eight bytes. The empty queue emits `[]`; a full wrapped queue retains logical
order. A head equal to capacity is normalized by subtracting capacity. This is
one conditional subtraction, not a general modulo operation for malformed heads.

## Nested values

The following field sequences are unconditional on successful serialization.
Offsets are relative to the named record, not its containing history object.

| Record / body | Ordered fields: key → offset → output |
| --- | --- |
| Settled outcome, `0x3c033f0` | `o` → 0 → outcome record; `f` → 168 → binary64/null; `d` → 144 → text |
| Outcome, `0x3c050b0` | `s` → 0 → exactly two side records; `n` → 64 → text; `d` → 88 → text; `D` → 120 → optional 20-byte address; `f` → 112 → binary64/null |
| Side, `0x3c05360` | `t` → 24 → unsigned decimal qword; `n` → 0 → text |
| Settled question, `0x3c03c10` | `N` → 0 → text; `D` → 24 → text; `u` → 48 → unsigned decimal qword; `o` → 56 → array of unsigned decimal qwords from the recorded tree iterator |

The side pair at `0x464ccd0` invokes the same record writer twice, with the second
address 32 bytes after the first. It is not a variable-length side list. The
question's `o` member uses the tree traversal at `0x37c4aa0`; this packet preserves
that full helper and the serializer's u64 load, but does not reconstruct tree
insertion, deduplication or corrupted-tree behavior. Relations receive a valid
ordered traversal as a boundary input.

The `f` field serializer masks the binary64 sign bit and compares the remaining
bits with `0x7ff0000000000000`. Infinities and all NaNs emit `null`. Finite values
are handed to the recorded formatter at `0x5d0e4c0`; exact float lexemes are an
explicit dependency boundary. The tests distinguish finite values, signed zero,
infinities and NaNs without claiming that Python's float spelling equals that
formatter.

The optional `D` address uses a zero tag for `null`; presence passes the next
20 bytes to the hex serializer with a 42-byte buffer. Its short-leading-nibble
option is disabled, so the output is a quoted `0x` followed by exactly 40 lowercase
hex digits, including leading zeroes. The same key `D` in a settled question is
ordinary text; the two record contexts must not be conflated.

Text pointer/length loads, escaping, integer formatting, field formatting and
object termination are retained as full context bodies. The structural fixtures
are synthetic. They do not originate from a live node and do not establish
reader acceptance, missing-field defaults, round trips, settlement transitions,
payout amounts or cryptographic verification.

## Evidence and controls

`verify.py` authenticates the entire pinned image before checking complete FDEs,
code bytes, direct and relocated call targets, source locations, data references,
incoming relocation sites, and the instruction spans in `obligations.json`.
GNU and LLVM exports retain full bodies rather than selected matching prefixes.
`records.json` gives exact extents, hashes, instructions and unresolved calls.
The standard static comparator deliberately rejects changed instruction, call,
data, relocation and unwind evidence even when its outer whole-image hash check
is bypassed by a negative control. No binary bytes are transplanted into an
implementation.

`relations.py` reads field lengths, literal addresses, member offsets, strides,
queue steps and scalar boundaries from actual instruction operands. It checks
the two-span queue relation against an independent modular-index oracle over
all lengths and heads up to capacity 32. Dense-row fixtures cover empty,
singleton, repeated and maximum u64 keys, preserving pair order. Bit-level
float classification is compared with the host's independent finiteness test;
full address hex is compared with the standard byte encoder.

Four counterfactuals change native evidence and must change the derived result:
the first history key, a queue's element advance, the nonfinite boundary and a
dense collection's key offset. These are static relations, not emulation of the
captured target. The tests do not treat self-authored fixtures as native execution.

Reproduction commands from the repository root:

```sh
python3 research/work-items/RE-001-node115-settled-outcome-history-text/verify.py
python3 research/work-items/RE-001-node115-settled-outcome-history-text/relations.py
python3 -m unittest discover -s tests -p test_node115_settled_outcome_history_text.py -v
make doctor
make verify test catalogue-check reproduce
```

Exact tool versions, commands, observed results and logs are recorded in
`validation.json`. No hosted CI, container success, target execution, native
source equivalence or full-component completion is claimed.

## Scope and prior work

GPT-6.1 Terra checked all visible open and closed PRs and retained unavailable
historical exclusions. The dated census and nearest-work assessment are retained
in `pr-census.json.bz2`, `scope-audit.json` and `overlap-summary.md`. Missing API
patches and inaccessible historical content prevent an absolute uniqueness
guarantee; this is an explicit comparison against the available evidence.

[#2123](https://github.com/lalalune/hyperliquid-source/pull/2123) owns the outer
state text export handoff and leaves child encoding unresolved.
[#1875](https://github.com/lalalune/hyperliquid-source/pull/1875) studies the
older OutcomeTracker object, with child codecs left open.
[#1674](https://github.com/lalalune/hyperliquid-source/pull/1674) covers spot
metadata, a different child of the spot state. Deployment admission in
[#997](https://github.com/lalalune/hyperliquid-source/pull/997), settlement text
parsing in [#1859](https://github.com/lalalune/hyperliquid-source/pull/1859), and
fraction/account projection in [#2885](https://github.com/lalalune/hyperliquid-source/pull/2885)
and [#2915](https://github.com/lalalune/hyperliquid-source/pull/2915) are separate
policy questions. This packet supplies the previously unclosed stored history
shape; it does not repeat those transitions or claim their acceptance gates.

New analysis and relations are independently authored under MIT. The evidence
and export scaffolding reuses earlier project-authored MIT packets. No unlicensed
inferred source was read or copied. A useful next step is the matching reader's
required/default/duplicate-field behavior, followed by an independently authored
Rust codec once both directions and primitive formatting requirements are closed.

The later overlap refresh is retained in `final-overlap-refresh.md`. Previously observed PRs absent from the refreshed listing remain overlap exclusions; unavailable historical contents, missing API patches and later work limit the conclusion.

The full 584-file suite ran on the history-text branch. Each companion branch independently matched the base input hashes and passed its own focused tests and integrity checks; `validation.json` distinguishes reused suite evidence from branch-specific commands. The original base had a stale generated README inventory count; regenerating the catalogue resolves that pre-existing check failure.
