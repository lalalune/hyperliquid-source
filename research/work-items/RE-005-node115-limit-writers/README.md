# RE-005 node115 reader-state limit writers

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/limit_writers_static.py`; retained
exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

The state-construction packet (#2501) closed with an open
question: who writes the limit qwords in the top dispatchers'
context objects (`[rbx+0x220]`, `[rbx+0x180]`, `[rbx+0xa60]`, and
the bulk-b top caller's `rcx` argument) — that is, what
ultimately decides how much a constructed reader may charge?
This packet answers it for the four top dispatchers.

## Result

The writers are the dispatchers themselves. Each of the four
top dispatchers receives its object as the entry `rsi` (saved
to `rbx`; bulk b saves it to `r13`), and every direct write to
the limit field inside the dispatcher is enumerated below
(access census cross-checked with two independent
disassemblies; no other direct access through the object
register exists in any of the four FDEs).

- bulk a (`0x2b67e50`, field `+0x220`, load at `0x2b68885` for
  the constructor call at `0x2b688b4`): two writes.
  (1) `0x2b6847a` stores the immediate 0 while a fresh
  five-qword record `(0, 60.0 bit pattern, saved register,
  copied pair)` is built at the field; the record helper
  `0x2b7a290` is then called on the field with its record tag
  byte (`+0x530`) set to 0.
  (2) `0x2b6874d` stores the final value: a byte-selected
  constant — the byte at `[rbx+0x1e8]` selects 1000 when it is
  0 and 4,000,000,000 (`0xee6b2800`) when it is nonzero
  (`cmovne` at `0x2b686fc`). The value is also stored to
  `+0x218` and `+0x248`. After the store, the parse helper
  `0x2b788e0` runs and, when its result is not the sentinel,
  the field is loaded into the constructor's `rcx`.
- bulk b (`0x5a64aa0`, field `+0xc40` of the `r13` object, load
  at `0x5a66d03` for the view-builder call at `0x5a66d32`):
  the codegen twin of bulk a. (1) `0x5a668e6` stores the
  immediate 0 with the same record build; the record helper
  called on the field is `0x5ab6ce0`, whose full 267-byte body
  is exported here and stores only at `+0x28..+0x48` and
  `+0x308..+0x310` of its record — never at `+0x0` — so the 0
  survives that call. (2) `0x5a66bcd` stores the byte-selected
  constant (selector byte `[r13+0xc08]`, same 1000 /
  4,000,000,000 pair, `cmovne` at `0x5a66b70`), also stored to
  `+0xc38` and `+0xc68`. This also resolves #2501's bulk-b
  boundary: the top caller's `rcx` at the view-builder call is
  exactly this `+0xc40` field.
- twin a (`0x2b69d20`, field `+0x180`, load at `0x2b6aa24` for
  the constructor call at `0x2b6aa53`): three writes, in stage
  order. (1) `0x2b69e69` stores `rcx = lea obj+0x140`, the base
  pointer of the record built in that stage; the field is read
  at `0x2b69f4d` and propagated to `+0x268`. (2) `0x2b6a68e`
  stores a 16-byte copy of the pair then at `+0x158/+0x160`
  into `+0x180/+0x188`, while a fresh record is built at
  `+0x168` and the record helper `0x2b7a290` is called on it.
  (3) `0x2b6a8e0` stores the final value `r13`, also stored to
  `+0x178` and `+0x1a8`.
- twin b (`0x5a6a640`, field `+0xa60`, load at `0x5a6b881` for
  the view-builder call at `0x5a6b8b5`): the codegen twin of
  twin a. (1) `0x5a6aad6` stores `lea obj+0xa20`; the field is
  read at `0x5a6ac0f` and propagated to `+0xb48`. (2)
  `0x5a6b4e7` stores a 16-byte copy of the pair then at
  `+0xa38/+0xa40`. (3) `0x5a6b732` stores the final value
  `r15`, also stored to `+0xa58` and `+0xa88`.

The twins' final value has two entries. On the copy entry
(twin a: `r13 = [obj+0x178]` at `0x2b69f05`, jump at
`0x2b69f21`; twin b: `r15 = [obj+0xa58]` at `0x5a6abcb`, jump
at `0x5a6abe7`) it is the sibling slot's current value. On the
compute entry it is derived from a source object pointed to
by the dispatcher object (twin a: `[rbx+0x78]`; twin b:
`[rbx+0x958]`): the source's full first qword is compared with 2 (giving
120), then its low32 bits are compared with 1 (giving
10,000); otherwise the value is
`min((end-start+1) * 10,000,000, 1,000,000,000)` over the
source's `+0x8` (start) and `+0x10` (end) qwords, saturating
to 1,000,000,000 on borrow or multiplication overflow. A flag
byte records `value >= 100,000,000` and is passed to the
downstream call as `r8d`.

Last-writer analysis: in each dispatcher's direct control
flow, the only instructions that can reach the limit load
without passing a limit store are the tail instructions
beginning immediately after the final store (the parse helper
call `0x2b788e0` / `0x5ab4390` and the result tag checks); the
dispatcher entry is not among them. The only jump-table
targets inside `(final store, load]` land inside the final
stage's own block, downstream of the store (eight pinned
table slots in `records.json`; bulk b has none). So when the
final stage is entered at or before its store, the loaded
limit is that store's value; when it is entered downstream of
the store, the field keeps its incoming value, whose writer
is an earlier arm above or the object's incoming state (see
Boundaries).

Caller census: no rip-relative `lea` references any of the
four dispatchers. Direct callers — bulk a: `0x2ad7ff7`
(FDE `0x2ad7140`) and `0x2cc52bf` (FDE `0x2cc1120`); twin a:
`0x2ae0454` (FDE `0x2ae0100`) and `0x2cb2101` (FDE
`0x2cb1eb0`); bulk b: `0x5a856d1` and twin b: `0x5a83698`,
`0x5a85a2c`, all three in the single FDE `0x5a82670`.

## Boundaries

- Who first set the values the final stores derive from —
  the bulk selector bytes, the twin sibling slots and
  source-object fields, and the incoming limit value when the
  final stage is entered downstream of its store — is above
  the traced window.
- The copy-a record helper `0x2b7a290` is pinned at its call
  sites only; whether its tag-0 arm writes its record's first
  qword is not traced (the copy-b helper is exported in full
  and does not). The sibling-record calls (bulk `0x27013e0` /
  `0x5860f30` on `+0x208` / `+0xc28`; twin `0x2701770` /
  `0x5861830` on `+0x150` / `+0xa30`) do not take the limit
  field address; their internal writes are not traced.
- The exit-path `lea` uses of the bulk fields pass the field
  address to `0x2abc7e0` / `0x5a52490` on dispatcher exit
  paths; those callees are identified by argument shape only.
- The writer of the twin-a stage result's `+0x28` field, the
  second half of #2501's next question, is a different field
  and remains open.
- Raw values are recorded mechanically; which Rust types or
  enum variants they belong to is not established.

## Files

- `records.json` — authenticated owners and frame records,
  per-dispatcher limit records (field, writes, loads,
  downstream calls), the selected and computed limit values,
  the last-writer tail slots, the record-helper store census,
  the full caller census, boundaries and limits.
- `record_helper_b.objdump.txt` — retained disassembly of the
  one traced function at most 4 KB (the 267-byte copy-b
  record helper `0x5ab6ce0`); the four dispatchers are above
  4 KB and are recorded by FDE span, body hash, frame records
  and byte pins instead.
- `frames.txt` — native readelf FDE lines for the five
  traced functions.
- `../../tools/limit_writers_static.py` — regenerator and
  verifier; `../../tests/test_limit_writers_static.py` —
  regeneration, limit-value, census and counterfactual tests.

## Next question

Who first sets the values the final limit stores derive
from — the bulk selector bytes (`+0x1e8` / `+0xc08`), the
twin sibling slots (`+0x178` / `+0xa58`) and source-object
fields (`[obj+0x78]` / `[obj+0x958]` targets) — and what
writes the twin-a stage result's `+0x28` field left open by
#2501?

## Ordered raw-tag widths

The two comparisons have different widths in both twins: CMP RCX,2 is64-bit, while CMP ECX,1 is32-bit. The generated tag_conditions entries retain the actual ordered masks, immediates, registers and VAs. For raw source word0x100000001 with start0/end9, both actual compute points select10,000; a full-qword equality interpretation of the earlier summary would select100,000,000 instead. These are raw-word observations, not a claim that this encoding is a valid original enum or live input. #2531 traces descriptor inputs but establishes no upper32-zero invariant. Original captures and native exports remain unchanged. The target-backed correction packet is ../RE-005-reader-budget-tag-width-115/.
