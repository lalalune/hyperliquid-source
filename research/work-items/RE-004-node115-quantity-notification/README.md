# Node #115 quantity notification: keyed row and aggregate effects

Partial HL115-094. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF virtual addresses; no captured execution/emulation or full gate claim.

## Prior work and consumer join

PR #2880's `src/node115-quantity-change/lib.rs` owns the ordered counter/optional
signed-total prefix of `0x4206f70`. This crate imports that unchanged module and
resumes its real `Boundary::Notify`; it does not recreate the prefix. Related
#2204/#2892 are credited quantity prior work. Optional total lookup remains open.

At `0x4207031..0x4207061`, descriptor +0x18 supplies the optional context pointer,
its first 20 bytes supply an address, saved original RDI supplies the u64 key, and
saved new quantity supplies RCX. A null context or unchanged caller quantity skips
the call. The target is `0x4483500`. Its behavior is an in-memory keyed row and
aggregate mutation; this packet does not treat the helper as sending a message.
The safe source adapter checks that the boundary's raw word matches the supplied
context identity. Binding a valid raw word to borrowed source storage is a premise,
not an arbitrary native pointer dereference or complete lifetime proof.

## Exact lookup and row fields

`0x4717860` finds an exact 20-byte address. Its singleton compares first16+last4;
its indexed path uses `0x3ee6af0`, whose predicate compares the same bytes in a
112-byte outer row at +0x58. The returned outer row owns an inner indexed map and
aggregate at +0x48. An absent address returns without changing state.

The inner singleton compares the supplied u64 key at +0x40 of its 72-byte row.
The multirow path calls shared hash `0x47172c0` then `0x3ed2d10`; the candidate
predicate checks that same full u64 key. This hash helper is prior work (#4316,
#2655 and open #5365/#5246/#4552), not a new algorithm claim. Index bounds are
checked before selecting a row. Missing key or stored quantity equal to the new
quantity returns without mutation.

The row fields consumed by `0x4483500` are multiplier+0, two raw side words+8/+16,
two raw budgets+24/+32, stored signed quantity+40, u32 divisor+48, and key+64.
Other bytes are opaque. The new decoder consumes precisely those fields. A nonzero
divisor is a defined-domain premise: its local rejection of zero does not invent a
native error return for a hardware division fault.

## Computation and write order

For a signed quantity q, choose index i=1 if q>0, else0. Let base=side[1-i],
other=side[i], budget=budget[i], a=unsigned magnitude(q), and p=a*multiplier
computed with overflow detection. Initially selected=base. When all these guards
hold, replace selected by max(base,min(candidate,other-2p)):

* 1 <= budget <= other;
* p <= 2^63-2 with no u64 multiplication overflow;
* twice a is representable and does not exceed budget;
* twice p does not exceed other;
* candidate=floor(other/budget)*(budget-2a) fits u64 and is <=2^63-2.

Return floor(selected/divisor). Failed numeric eligibility uses the base, rather
than clamping an arbitrary candidate. An INT64_MIN magnitude can instead reach a
diagnostic call after the first two guards: this is an explicit stop below.
No economic names or units are inferred from these raw fields.

The helper computes old_cost using the row's **stored** quantity, writes new
quantity at `0x4483692`, then computes new_cost. It computes aggregate+new_cost
before subtracting old_cost, and finally stores aggregate at `0x448377e`.
The caller's previous quantity is not passed into this helper; equating it with
the stored quantity would silently add an invariant absent from this evidence.

At `0x64e4ea8 -> 0x4524e40`, diagnostic behavior remains a prerequisite. The source
returns `StopBefore` without calling a fabricated diagnostic or assuming it returns:

| Boundary | Stored quantity at stop | Aggregate at stop |
| --- | --- | --- |
| Old-size diagnostic | old | unchanged |
| New-size diagnostic | new | unchanged |
| Aggregate-add overflow | new | unchanged |
| Aggregate-sub underflow | new | unchanged |

The native continuation after a returning aggregate diagnostic saturates the
addition/subtraction; that continuation is visible in the packet but intentionally
not executed by this model. In particular the operation cannot be advertised as
atomic on diagnostic/unwind paths. Malformed indexed maps, hashing, helper failure,
concurrent writers and object lifetime beyond this call remain unclosed.

## Validation

```
python3 research/work-items/RE-004-node115-quantity-notification/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-quantity-notification/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-quantity-notification/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-quantity-notification/Cargo.toml -- --config skip_children=true
cargo +1.95.0 clippy --manifest-path src/node115-quantity-notification/Cargo.toml --all-targets -- -D warnings
```

Ten tests pass in both profiles: eight new and two imported prior tests. A widened
signed-arithmetic formula checks 32768 bounded cases independently of native
wrapping/borrow handling. Other tests cover exact address/key identity, real prior
prefix composition, context mismatch, stored-old versus caller-old, row neighbors,
zero budget, full-width product, divisor validation, INT64_MIN precedence and each
diagnostic stop's write order. Formatting and Clippy pass under Rust1.95.0.

`verification.json` preserves static denominators and rejected semantic controls.
Python/Capstone5.0.7 verifies digest, FDEs, instructions and helper bindings, then
rejects comparator/field/branch/arithmetic/edge corruptions beyond hash-only guards.
Repository checks are reported in the PR. Static/source tests do not establish
executed native equivalence. All gates remain false; new source/evidence are
independently authored under MIT without copying unlicensed inferred code.
