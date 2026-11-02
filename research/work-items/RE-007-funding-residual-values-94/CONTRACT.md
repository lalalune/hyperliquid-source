# Supplied-summary residual application

Pre-code contract. No production implementation, client, build harness or
source qualification exists in this packet. The binary is Linux x86-64 node94,
SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

The recovered operation consumes a supplied finite stream of worker-shaped
summaries and observes an explicit state snapshot after the opaque worker
bridge has completed. It does not compute funding rates or execute the worker,
and it does not describe the whole entry-to-return state change of `3703f20`.
The worker's changes precede this snapshot. The selected user and position
remain live and stable through residual application.

Each summary has a unique opaque20-byte key, signed i64 sum, optional
`(asset:u64,magnitude:u64)` selection, and a finite vector of opaque72-byte
records. The native value's full64-bit tag at+32 is exactly0 or1. When present, the native selected-address
payload equals the summary key. These are supplied-stream/provenance premises,
not a target validation routine or a proof of parallel scheduler completeness.
The record's little-endian u32 at bytes60..64 is the inner-vector sentinel.
All other record bytes are preserved without financial interpretation.

State contains unique address-keyed users, each with signed cross balance,
unsigned position count and a unique u64-asset position map. A position has
raw u32 mode, u32 leverage, signed margin and signed size. State also contains
the ARU address set, signed auxiliary values keyed by u64 asset, and the
users-with-positions address set. Unrelated users, positions, keys and fields
are preserved. Safe value types do not reproduce native layout or allocator. All represented
field bytes are supplied and initialized; inactive margin/cross fields are
preserved opaque bit patterns, not evidence that a native constructor initializes
or interprets them. Raw mode values are a byte-level branch contract, not a
claim that arbitrary values are valid variants of an original Rust enum.

For valid supplied summaries, sort by unsigned lexicographic address. Fold the
signed sums from zero using saturating i64 addition in that order. Choose the
first present selection with maximum **unsigned** magnitude; ties preserve the
earlier address, including magnitude0. Concatenate each inner record prefix
before its first zero sentinel, in address order. A zero sentinel discards its
own inner suffix, not later summaries. Flattening precedes residual mutation.

If total is zero or there is no selection, return those records with state
unchanged. In particular, missing unused users/positions or unused sizeMIN
do not require access or rejection. Otherwise the selected key and selected
asset must already exist, and selected size must differ from i64::MIN. Insert
the selected address into ARU. If raw position mode equals1, replace its margin
by `sat_sub(margin,total)`; every other mode replaces the user's cross balance
by `sat_sub(balance,total)`. Preserve position size, leverage and user count.

Let `a=abs(size)` and `x=aux[asset]` or0 if absent. Insert an absent asset with0,
then store `sat_sub(x,a)` and `sat_add(previous,a)` in that order. The final
value is `max(x, i64::MIN+a)`. This may change a negative signed value, and an
absent entry becomes present even at size0. Equal old/new sizes imply unchanged
position count; the later leverage-update and users-with-positions branches
are not taken under the frame assumptions. They are not treated as inert
callbacks. All arithmetic is raw integer arithmetic; economic units and a
conservation theorem are unproved.

Native correspondence requires valid finite balanced trees/control tables,
exact lengths/capacities, checked nonwrapping spans, readable/writable lifetime
and nonaliasing invariants. Required allocation/copy/free, initialization and
diagnostic calls return normally with the explicit frames in CALL-FRAMES.md.
The earlier worker has seen state pointers: ABI register preservation alone
does not establish the required memory frame. No concurrent or later opaque
mutation of the admitted state, keys, rows or tree shape is allowed.

## Separate prospective safe-source admission policy

This policy is outside the native equivalence statement. A safe implementation
may reject duplicate summary keys and impossible span/count admission before
state mutation. On an actually active residual only, it rejects missing selected
user, then missing selected position, then sizeMIN, in that order. No check of
those unused fields is made on the zero-total/no-winner path. Typed rejection
retains initial state; no native panic rollback behavior is implied. Duplicate
summary rejection has priority even if a zero residual would otherwise skip
state access. The supplied native tag/address constraints are represented by
typed input fields rather than guessed constructors.

Ordinary allocation success remains a premise; allocation failure, arbitrary
drop side effects and panic/unwind behavior are not made atomic by this policy.
The native sizeMIN path can acquire/insert the auxiliary entry and panic after
the caller has already inserted ARU and debited a balance/margin. It is excluded
from ordinary native-corresponding cases, not misreported as an early rejection.

Vacant account/position construction, worker computation/scheduling, rates,
premium reset, timing/diagnostic output, native ABI/capacity/refcount identity,
filesystem/network activity and live economic validity remain outside scope.
Merged PR899 is prior credit for the host/sorted-summary outline. Its stubbed
state effects and inferred largest-position-size meaning are not an oracle;
the magnitude field stays explicitly supplied and uninterpreted here.
