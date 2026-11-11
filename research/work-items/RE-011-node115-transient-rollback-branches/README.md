# Node #115 transient rollback: zero and absent entries

Backlog HL115-073. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF virtual addresses and static disassembly; no captured execution or
emulation, no physical hash-table equivalence or full-component completion.

## Prior work and gap

#3930 recovers TLOAD/TSTORE and lookup; #4356/#4367 cover writer behavior.
Open #4363 owns tag10's nonzero restoration into an existing address/key and
explicitly excludes zero-old and missing-entry behavior. #4366 owns separate
cleanup. This successor reuses those boundaries and closes the excluded branch
policies plus the inner erase's occupancy/control metadata. It does not claim
another reconstruction of the existing-key restoration stores.

## Native branch result

The relative dispatch entry at `0x942270` binds tag10 to `0x5be372b`. The record
contains address bytes+1..21, key bytes+24..56 and old value bytes+56..88. Padding
between address and key is not read as part of either identity. The handler's
third argument is the optional transient context; null returns without mutation.

All32 old-value bytes are OR-tested. If zero, `0x5be3340` looks up the exact20-byte
address through `0x5be2460`. A missing address returns without inserting it.
An existing address goes to `0x5be1140` to remove the exact32-byte inner key.
A missing inner key returns without a store. A hit removes it, even when the
current stored value is itself zero. No branch removes the enclosing address
when its last inner key disappears. The handler ignores the returned removed
value; the table's inner key count, not outer membership, changes.

If old is nonzero, `0x5be1e70` returns either the existing address's inner map or
a vacant outer entry. The owner inserts a missing address with a fresh inner-map
state, increments outer item count, and then invokes `0x5be1fd0`. This helper
restores an existing exact32-byte key (credited #4363) or inserts the missing
key/value and updates inner count/control bytes. Thus missing state does not
cause a silent skipped restoration on this branch. Allocation/growth can be
required: `0x64e6d78 -> 0x5be16e0` and `0x64ec280 -> 0x5be12a0` are explicitly
unclosed structural prerequisites for successful creation.

## Erase metadata

On a matched inner slot, `0x5be1140` examines two16-byte control groups: one
starting16 buckets before the slot (masked), the other at the slot. Let `L` be
the number of non-empty controls at the end of the first group and `R` the
number at the start of the second, each capped at16. The comparison is `L+R>15`:

* Dense span: store deleted marker0x80 and leave growth allowance unchanged.
* Shorter span: store empty marker0xff and increment growth allowance.

Both cases write the ordinary control and its mirrored byte at
`((slot-16)&bucket_mask)+16`, and decrement items once. Only0xff counts as empty
in the two group masks; a prior0x80 tombstone is not an empty termination marker.
The value payload is returned separately. The owned `erase_controls` function
performs these actual metadata writes on supplied control storage. Its shape and
counter errors reject malformed source inputs; they are not native error paths.

## Owned scope and validation

`src/node115-transient-rollback-branches` decodes the selected record and applies
its logical mutation to real owned nested maps, preserving empty outer entries.
The record is borrowed and unchanged. Native journal popping/commit belongs to
an outer owner and is not inferred from this handler; there is no invented
journal-consumption operation in the source.

Seven tests cover missing address/key, zero removal and retained outer state,
nonzero creation/restoration, null context, exact record offsets, empty/deleted
control markers and mirrored writes. A distance-based oracle checks272 left/right
empty-neighbor configurations against the observed erase branch. This is a
source integration witness and static contract, not executed native behavior.

```
python3 research/work-items/RE-011-node115-transient-rollback-branches/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-transient-rollback-branches/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-transient-rollback-branches/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-transient-rollback-branches/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-transient-rollback-branches/Cargo.toml --all-targets -- -D warnings
```

Python with Capstone5.0.7 is required. Verification authenticates whole target,
FDEs, dispatch entry,611instructions and619facts across nine selected windows.
Twenty-one semantic controls change dispatch, branch, lane offsets, erase
threshold/markers, mirrored writes, counts and helper edges. Their rejection
checks semantics after authenticating the original file, not only whole-file
hash mismatch. Repository check outcomes are recorded in the PR.

Hash production, full probe/growth correctness, allocation failure, physical
map layouts and outer revert/commit ownership remain open. Valid tables and
successful structural helpers are premises. All gates remain false. New source
and evidence are independently authored under MIT; no unlicensed inferred code.
