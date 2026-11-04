# RE-005: where the `chain` entry is first inserted — inside the registry worker and the merge builder

Question left open by the RE-005 chain-origin packet (#2486): the
`chain` string the apply function reads through the getter `0x4e4ca30`
materialises only inside the registry worker `0x1630c90` (path A) or
the merge builder `0x1667780` (path B). Where, inside those two
bodies, is the `chain` entry first inserted into the map the getter
later reads — with what key material, and where does the inserted
value come from?

## Verdict

**Path B (merge builder `0x1667780`, 2,679 B): the drain insert.**
The builder never creates a key and never references the `chain` key
bytes at `0x92a7be` (lea census and raw dword census both empty). It
calls the shared insert-or-replace helper `0x1669390` exactly twice:

- `0x1667c0e` — the pair loop stages a value record into the
  caller-supplied **temp** table (map argument = temp header), keyed
  by the pair's own (ptr, len). This site is reachable only below the
  ctx-match fall-through: the pair key is first probed in the ctx
  (hash `0x1665f10` at `0x1667cdd`, bcmp via slot `0x64df9f8` at
  `0x1667868`); a ctx miss exits through the empty-group edge at
  `0x16678b8` to the next-pair edge with **no insert**.
- `0x1668034` — the drain loop inserts each occupied temp entry into
  the map the getter reads: the map-header argument is `ctx + 0x18`
  (the entry saves advance `r12` by the single `+0x18` add at
  `0x1667ee6`), the key is the temp entry's own ptr/len, and the
  value is the temp entry's value copied via `0x16595d0` at
  `0x1667fd9`. The displaced old value's head is compared against
  the sentinel at `0x166804f` and dropped when different.

So in path B a `chain` entry reaches the getter's map only through
the drain insert, and only if the temp table holds a `chain` entry
at drain time — either pre-existing in the core-built temp, or
staged by the pair loop when a spec pair's key is `"chain"` **and**
`"chain"` is already present in the ctx (otherwise the pair is
skipped without inserting).

**Path A (registry worker `0x1630c90`, 17,970 B): no insert into the
result map inside the worker body — proven negatively.** The worker
contains no direct or slot call to the insert helper `0x1669390`, no
inline hashbrown probe/insert (no pcmpeqb/psubq/tzcnt census hits),
and never references `0x92a7be`. Its only insert-capable calls are to
the get-or-insert helper `0x1667540`, and every one of them targets
the **ctx** (the worker's third argument), never the result pointer:

- worker sites `0x16327b9` (key = the spec entry's name at
  `+0x170/+0x178`) and `0x163281e` (per-element string keys of a
  16-byte-element array), both via slot `0x64e1ba8` with `rdi = ctx`;
- counter callee A `0x162cee0` at its site `0x162cf0b` — the worker
  passes the ctx as its fourth argument at `0x1631e42`; key from its
  third argument's `+0x78/+0x80`;
- counter callee B `0x163a070` at its site `0x163a239` — the worker
  stores the ctx as its first stack argument at `0x1631c7f`; key =
  the spec entry name at `+0x170/+0x178`.

A whole-binary census of slot `0x64e1ba8` finds exactly these four
call sites. The helper's inserted default record cannot carry a
getter-readable string in any case: its word at value `+0x28` — the
getter's presence gate — is 0; its counter word at `+0x30` starts at
1 and is incremented on a hit. The worker's three remove-op calls
(slot `0x64e1c70` → `0x16683e0`, sites `0x16317bf`/`0x1632743`/
`0x1634350`) likewise target the ctx and *delete* entries (items
decrement at ctx `+0x30`, growth-left increment at ctx `+0x28`,
tombstone control bytes). A one-level capability census over all 49
remaining FDE-bounded worker callees finds the insert helper
reachable only from get-or-insert itself, and no callee with inline
growth accounting; the descriptor tables the worker dispatches
through never name any of the three map helpers.

The worker fills its result's table header by direct field stores
from frame-local structs at its exits, and on one exit path
delegates to the final-assembly callee `0x164df60` (23,327 B) at
`0x16343d1` with (result, three frame structs, ctx). The first
insertion of a `chain` entry into the path-A result map is therefore
not in the worker body: it is inside those struct builders or the
final assembly (hash-pinned boundaries below), or the result table
arrives pre-built from them.

## Shared map evidence (re-pinned here)

- Insert-or-replace `0x1669390..0x1669656` (710 B): hashbrown-style;
  state at header `+0x20` via the temp hash `0x1665da0` (call at
  `0x16693ca`); growth-left test at header `+0x10`, reserve via slot
  `0x64e1de0` → `0x16663d0` at `0x166961f`; replace swaps the 0x38-byte
  value (stores at `0x1669551`/`0x1669564`) and returns the old value
  in the out-record; fresh insert stores the control byte
  (`0x1669588`), the key ptr/len (entry `+0x0`/`+0x8`), the value
  record (entry `+0x10`) and writes the sentinel
  `0x8000000000000000` to the out-record.
- Get-or-insert `0x1667540..0x166777e` (574 B): items gate at map
  `+0x30`; hash `0x1665f10` over the state at map `+0x38`; on a hit
  it increments the counter at entry `+0x40`; on a miss it builds
  the default record (presence word 0, counter 1) and calls the
  insert helper with the header at map `+0x18` (`0x16676bd`).
- Remove op `0x16683e0..0x16688de` (1,278 B): descriptor-driven
  iterator; appends converted items to a vector argument; on a ctx
  match it removes the entry (see above). It never calls the insert
  helper.
- Getter read (reference body, re-pinned from #2486): items gate
  `[map +0x30]`, hash `0x4e52640` over the state at map `+0x38`; on a
  key match the word at entry `+0x38` must be nonzero, then the
  string is `([object +0x8], [object +0x10])` of the object at entry
  `+0x30`.

Map layout (shared by all five bodies): value 0x50 B — prefix
`+0x0..+0x18`, table header at `+0x18` (buckets `+0x18`, mask
`+0x20`, growth-left `+0x28`, items `+0x30`), hash state `+0x38`,
inner pointer `+0x48`. The standalone (temp) header form is buckets
`+0x0`, mask `+0x8`, growth-left `+0x10`, items `+0x18`, state
`+0x20`. Entry stride 0x48: key ptr `+0x0`, key len `+0x8`, 0x38-byte
value record at `+0x10`.

## Packet contents and the size rule

Owners with full disassembly exports: the merge builder, the insert
helper, get-or-insert, the remove op, the value copy helper
`0x16595d0`, and the two counter callees (all ≤ 2,679 B); the getter
is committed as a reference body, mirroring #2486. The registry
worker is 17,970 B, so per the established size rule it is pinned by
its full-body sha256 plus eight committed segment windows covering
every map-relevant region (entry saves, all three map-operation
clusters, the result-exit stores, the final-assembly call); every
asserted site in the full body is additionally validated as an
instruction start at generation time, and the body-wide censuses
(insert calls, slot calls, lea targets, raw key-address
occurrences) run over the full body in the tool.

`tools/chain_entry_insert_static.py` regenerates `records.json`,
`frames.txt` and all exports from the authenticated artifact and
re-derives every pin, relocation binding and census, including
hash pins for 11 named boundary bodies and all 49 remaining
FDE-bounded worker callees.
`tests/test_chain_entry_insert_static.py` asserts regeneration
byte-identity and counterfactual rejection (mutated insert calls,
mutated default-record presence word, mutated remove-op decrement,
mutated ctx-miss edge, mutated slot binding, mutated descriptor
pointer, mutated boundary body).

## Boundary

What the final-assembly callee `0x164df60` and the worker's
frame-struct builders (`0x162f9c0`, `0x162fc50`, the predecessor
`0x16300c0` — the counter callees' only other caller — and the
per-entry helpers) write into the structs the worker copies into
the path-A result is inside those hash-pinned boundaries. Likewise,
who first writes a `chain` key into the path-B ctx, the core-built
temp, or the spec entry array the pairs are taken from is upstream
of the core boundary pinned by #2486. Which of paths A/B a given
run takes, and the runtime contents of the registry, are execution
facts outside static evidence. No captured code was executed.

## Independence

#2486 owns both bodies as hash-pinned boundaries only; no merged
record and no other open PR traces their insides or the two counter
callees' get-or-insert sites (census over the 24 merged
`records.json` files and the open queue's titles, branches and head
file lists at build time). This packet answers #2486's recorded
next question for the two bodies it named.

## Next question

For path A: which of the worker's frame-struct builders — or the
delegated final assembly `0x164df60` — first writes a `chain` entry
into a value-layout table, and can the ctx table the worker's
get-or-insert pass counts spec names into be the same table the
result is later copied from? For path B: who first writes a `chain`
key into the registry ctx the builder merges from, or into the spec
entry array the pairs are taken from?
