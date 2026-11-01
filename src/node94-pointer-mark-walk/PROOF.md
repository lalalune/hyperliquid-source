# State relation and admitted domain

The target is node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The leaf is exactly `[0x50e69f0,0x50e6a82)`, 146 bytes and 38 decoded
instructions. Addresses here are ELF virtual addresses, not file offsets.
The function and next FDE, complete leaf bytes, four complete caller bodies,
CIEs, padding and all direct caller sites are locked by the frozen static facts.
No callee is present. This proof covers the leaf's state changes on the admitted
snapshot domain; it does not establish the complete callers' behavior.

## Read and write relation

Let `A` and `B` be the initial RDI and RSI. The instruction observations are:

- `0x50e69f4..0x50e6a02`: load `P=[A+0x68]`, then `M=[P+0x108]` once.
- `0x50e6a02..0x50e6a14`: load tail begin/end at `B+0x50/+0x58`, subtract
  modulo 2^64, arithmetic-shift right by three, and add `[B]` modulo 2^64.
  The zero flag from that addition skips all entries when the sum is zero.
- `0x50e6a16..0x50e6a41`: the running tail cursor starts at `begin-64` and
  advances by eight after every entry. Unsigned `i>7` selects that cursor;
  otherwise reload `[B+0x48]` and select its slot `i`. Thus entry `i>=8` uses
  tail slot `i-8`, independent of `[B]`.
- `0x50e6a41..0x50e6a53`: load the selected entry pointer, then head pointer
  `[entry+0x8f8]`, then current link `[head]`. Equality with head skips the walk.
- `0x50e6a67..0x50e6a74`: load payload node `[current+0x10]` and compare its
  stamp `[node+0xcc8]` to `S=0x00ffffffffffffff`. Only equality enters the step.
- `0x50e6a58..0x50e6a65`: read `next=[current]` before writing `M` to the
  **old current link's payload** stamp. Head equality ends that entry before
  any head payload access; otherwise repeat the stamp gate on `next`.
- `0x50e6a74..0x50e6a81`: increment entry and cursor, continue until the entry
  counter equals the previously computed count, then return.

The selected slot, entry, head, link, and payload node are distinct roles.
Nothing here recovers their original type names or application meaning.

## Projection premises

The input arrays represent the heads obtained from the entry indirections.
The fixed inline array contains eight heads. The tail represents a valid
forward pointer-array span with byte length `8*t < 2^63`, no subtraction wrap,
and element count `t`. Rust's valid `u64` slices on the supported 32/64-bit
pointer widths satisfy this length bound. Therefore the target's signed shift
of the raw difference is exactly `t`, and its count is `(base_count+t) mod 2^64`.
Other raw spans, including reversed, malformed, or overflowing spans, are
outside this API. `base_count` remains any `u64`; it is not constrained to eight.

Opaque IDs name cells in two maps. Each map has unique nonzero IDs. Equal
payload-node IDs in any links denote the same stamp, so sharing is preserved.
IDs may coincide across the two namespaces; this does not assert that their
physical fields overlap. Link `next` and `node` values, selected entry/head
fields, array slots, and count metadata remain immutable and do not overlap
any stamp cell. Distinct stamp IDs denote distinct, nonoverlapping u64 cells.
Arbitrary partial byte aliases and concurrent changes are excluded. The mark
is the value of the initial two loads; supplying it does not reproduce their
pointer validity or fault behavior. No original ABI, pointer allocation,
unused fields, or RAX return value is claimed.

Map validity is checked before any state changes. Invalid maps produce the
new `InvalidMap` refusal even for a zero count. For valid maps, lookup failures
occur only at a reached read; earlier state changes are retained. MissingEntry,
MissingLink and MissingNode are safe API refusals, not original return values
or a recovered fault policy. Reached valid cells may have arbitrary u64 values.

## Equivalence and bounds

Induct on entries. Before entry `i`, all earlier state writes agree, the count
is fixed, and the running target tail cursor is `begin-64+8*i` modulo 2^64.
For `i<8` the inline selector is exact. For `i>=8` that cursor equals the
selected tail address. A missing slot is refused at this read. The head's next
link is loaded even if it immediately equals the head; the head's payload is
never needed in this case.

Induct on steps in an entry. The source resolves the same current link and
shared payload cell. A non-sentinel stamp stops without a store. A sentinel
stamp causes the next link value to be saved, then the old payload to receive
`M`, then the cursor to advance. Returning to the head ends before another
payload read. These statements remain true when multiple links or entries
share a stamp. In particular, with `M != S`, encountering any already marked
payload stops the entry. The first non-sentinel value is never overwritten.

Let `L` be the number of link-map records. The Rust loop admits at most `L`
sentinel stores, then checks the reached link, payload and sentinel gate once
more before a cycle refusal. If those checks succeed and the cursor is not
the head, more than `L` visits cannot be distinct. The link successor graph
is immutable. If `M != S`, a repeated link's shared payload would already be
non-sentinel and would stop at the gate, so this refusal cannot occur. If
`M == S`, all visited stamps remain sentinel and a repeated off-head link
establishes a cycle that cannot terminate in the target. The new
`NonterminatingCycle(entry)` records that refusal without inventing a target
return. Its bounded prefix stores preserve the same values. Gate and missing
cell checks precede the bound; they are never hidden by a premature cycle test.

Each successful outer step increments `i` from a value strictly below the
u64 count, so it cannot overflow even when count is `u64::MAX`. Missing tail
slots are refused before any out-of-range indexing or conversion. There are
at most `min(count, 8+t+1)` entry attempts on finite supplied data. Valid slices
bound `L` below `usize::MAX`, so the inclusive step range cannot overflow.
The source uses no allocation, unsafe code, shifts, or native dereferences;
all remaining index operations are statically bounded or checked. Map
validation and lookups favor an explicit finite domain over a performance
claim.

## Independent oracle and controls

Before any new Rust existed, `oracle.py` froze complete target admission facts,
86,147 input-only cases, and expected statuses plus final stamp values. For each
entry its oracle constructs the immutable functional-graph orbit while
ignoring stamp outcomes, records a deferred head/missing/cycle terminal, and
then chooses the earliest initial non-sentinel or repeated-payload barrier.
It batch-updates the admitted prefix. This differs from the Rust mutation loop
and preserves the precedence of earlier barriers over unread missing cells.
A closing link cycle is a barrier for a changed mark and nontermination for
an unchanged sentinel mark. Earlier entries' updates feed later entry orbits.

Fixtures exhaust all successor graphs on one through three non-head links,
all payload-sharing assignments, all sentinel/zero initial stamps, and three
mark values; they also cover fixed inline/tail boundaries, wrapping counts,
mark-width and ID boundaries, missing data, invalid maps, and 4,096 seeded
additional layouts. The input-only native client receives no oracle or expected
results. Opt0 and opt3 each run two independent builds; exact executable,
library, and stdout hashes repeat at each level. Thirteen separately compiled
wrong sources produce real output mismatches, with successful-original-case
counterexamples retained. Twenty-three static byte/relocation controls are
rejected, and a separately corrupted expected output changes one comparison.

Store/next-load order is established from the retained instructions and the
source. It is not falsely advertised as a behavior-distinguishing native
control under the disjoint-field premises. Captured instructions, the prior
packet's interpreter experiment, and any unlicensed inferred implementation
are not used as native oracles. This is a proof and sampled validation of the
stated state projection, not original x86 machine-code equality or a full node.
