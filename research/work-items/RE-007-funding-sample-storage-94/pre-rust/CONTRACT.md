# Pre-Rust contract: one returned record stream

This contract is a chronological extension of the static phase. The original
`../FINAL-FREEZE.json` and `../MANIFEST.sha256` remain unchanged. No Rust source,
Cargo manifest, Rust driver or compiled candidate exists for this component at
this freeze. Source construction requires the coordinator's review of this
contract, plan, oracle and corpus.

## Narrow value operation

Inputs are:

* `S`, a finite map from unsigned u64 keys to finite sequences of raw u64 words;
* `F`, a finite map from unsigned u64 keys to raw u64 words;
* `d`, one u8 dex byte;
* `R`, a finite ordered sequence of records `(key:u64, tag:u64, payload:u64)`.

All u64 bit patterns are admitted as keys, tags and payloads. They are integers
or raw bits, not prices, floats, enums or public asset-policy values.
Let `m` be the index of the first record with **full unsigned tag equal to 2**,
or `len(R)` if none exists. Define `P = R[0:m]`.

For each key k, collect the ordered sequence

`A(k) = [r.payload for r in P if r.key == k and r.tag % 2 == 0]`.

The new sample map has keys `keys(S) union {k | A(k) is nonempty}` and values

`S'(k) = S(k, default=[]) concatenated with A(k)`.

In particular an initially present empty vector remains present even without
an append, an absent key is created only when it receives an even-tag record,
and unrelated entries are preserved. Each appended payload retains all 64 bits.

If `d != 3`, `F' = F`. If `d == 3`, keys receiving at least one odd-tag record
in `P` receive the payload of their **last** such record; all other keys retain
their initial value. A missing fallback key is inserted. Odd-tag records do not
create or alter sample vectors. Even-tag records do not alter the fallback map.
The sentinel and all later records affect neither state.

The stop condition precedes parity. Thus tag 2 stops; tags 0x102 and
0x8000000000000002 append; tags 3 and 0xffffffffffffffff follow the fallback
branch; tag 0x8000000000000000 appends. A low-byte-only stop is incorrect.

The operation returns no additional semantic result: its observable value result
is the two updated maps. It performs no I/O, scheduling, clock read, allocation
policy selection, reporting, crypto operation or economic calculation.

## Bridge from the established native proof

The pinned artifact is Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The relevant host interval starts with a valid returned record vector at
`0x222b248` and ends at record-loop exit `0x222b480`.

Define an abstraction `alpha` only on the valid native states in the static
proof. Traverse active key/value entries of the finite well-formed native sample
B-tree and retain each vector's active first `length` u64 elements; discard
capacity, allocation addresses, unused slots and padding. This produces S.
Traverse the active native fallback B-tree entries to produce F. Decode the
returned record vector's active 24-byte rows as three little-endian u64 words
to produce R. The observed byte at dex+0x230 gives d. Unsigned native key order
corresponds to Rust's ordinary `u64` order.

The static proof establishes these native value steps under its explicit
allocator/copy/ABI/frame premises:

| Native operation | Abstract effect |
| --- | --- |
| Full tag compare at 222b2b4, branch to 222b480 | Stop before the sentinel |
| Low-bit test at 222b2c5 | Select even append or odd fallback |
| Existing sample search and append at 222b295/29c | Append one unchanged u64 |
| Missing sample adapter 287a610 and complete insertion 1a7cc90 | Add absent key with empty sequence, preserve old active associations |
| Fallback byte guard at 222b2c9 | Only d==3 updates F |
| Existing replacement at 2851687/68c | Replace one raw fallback word |
| Missing fallback adapter 2851610 and complete insertion 1a89610 | Insert absent key, preserve other associations |

The insertion induction includes full leaves, cascading full internal-node
splits, child parent/index repair, root growth and the returned inserted-value
handle. Therefore the abstraction is meaningful for missing keys as well as
existing ones. Under the same premises, the native state after each processed
record abstracts to the corresponding finite sequence update. Induction over
P yields exactly S' and F' above. Early tag2 establishes the prefix boundary.

The proposed Rust component uses owned `BTreeMap<u64, Vec<u64>>` and
`BTreeMap<u64, u64>` for these **abstract active states**. It does not implement
the captured B-tree memory layout, allocator, capacity growth, parent pointers,
LSDA, ABI or register effects. Matching S'/F' is the intended value-projection
claim, not byte identity or a full host reconstruction.

## Allocation, refusal and frame limits

The native abstraction requires finite valid nonaliasing input spans, valid
B-trees/vectors, nonwrapping allocation/count arithmetic, sample and record
capacities below the meaningful `2^63` niche, and the precise normal allocator,
copy, cleanup and memory-frame contracts in `../PROOF.md`. Those requirements
are not proven merely by a native function returning normally.

The Rust relation applies when its finite input states and resulting sequences
are representable on the build target and all required standard-library
allocations succeed. The caller supplies owned valid Rust values; there are no
raw pointers or native-layout inputs to validate. Allocation failure, capacity
overflow, panic, abort, unwind, partially applied state and rollback equivalence
are outside the claim. The component will not invent a `Result`, refusal code,
capacity policy or transaction/rollback API. Native failure and resource behavior
is not reproduced by this value projection.

The function may mutate only its two supplied maps. It must preserve unrelated
entries and input records. No opaque native helper is called by the Rust value
implementation, and no claim is made that it implements those helper contracts.
The correspondence is conditional on those contracts at the native side.

## Excluded scope

This is one explicitly supplied returned record slice. It does not construct
records, compute premium/oracle values, schedule assets, establish all-asset
coverage or a global ordering, implement the host's outer min-length pairing,
or extend state preservation past the native `0x222b480` boundary. Adding a
paired-stream API would invent a new interface around the unresolved producer
and scheduler, so the outer minimum remains static context only. The temporary
fallback map's later reporting, cleanup and lifetime are excluded.

The selected producer's stronger canonical tag0/tag1 result is credited context.
The consumer's demonstrated handling of every other u64 tag is preserved in
this contract; it is not silently narrowed to producer-only inputs.

## Independent pre-source expectations

`oracle.py` defines expectations with a declarative first-sentinel prefix,
per-key filter/group concatenation, and last-odd selection from the reverse
prefix. It imports no Rust candidate or existing implementation/model. Hand
cases assert explicit expected states before any general corpus generation.
The planned Rust source will use a sequential loop and standard-library map
operations. Corpus inputs and expected bytes are frozen before that source
exists. The corpus tests value projection; it is not captured execution.
