# Node #115 bridge request mutation before aggregate subtraction

Partial HL115-066. Target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are original ELF virtual addresses. No target execution or emulation.

## Prior work and remaining boundary

PR #2218 establishes the wrapper's result gate and aggregate subtraction, leaving
`0x3689150` opaque. This contribution closes the helper's keyed logical mutation,
its fresh nested singleton, and the exact state visible before the wrapper's
balance panic. Historical #871/#497 concern node #94 and supply no transferable
node #115 implementation proof. Transaction ownership, outer rollback and unwind
remain open. The resulting source is a bounded owned-state reconstruction; it
cannot establish that a partially mutated native request persists after an unwind.

## Key, value and native handoff

`0x44d83f0` constructs two 32-byte inputs. The outer key contains original R8's u64
word at +0 and original RSI's 20 bytes at +8. The nested request key contains the
amount (original RCX) at +0 and original RDX's 20 bytes at +8. The last four bytes of
each key are padding, not initialized by this wrapper. No timestamp/nonce or
address-role name is needed to establish the mutation.

The wrapper passes owner+0x80; `0x3689162` adds 0x18, so the mutated outer map is at
owner+0x98. `0x3ccc690` returns occupied/vacant entry tags. The flat search
`0x455a430` and tree comparison compare 20 address bytes first, then the unsigned
u64 word. They do not include the four padding bytes in identity. An occupied
entry causes result word 0x9e and skips value construction. Existing logical
values are preserved even if the submitted recipient or amount differs. The
entry helper can change native representation; this is not a claim of bytewise
storage immutability on duplicates.

On vacancy, `0x3689185..0x36891c7` initializes a fresh empty tree and a 64-byte
nested value with qwords `[0,8,0,0,0,8,0,0]`. `0x37079a0` takes its empty-tree arm:
allocates 0x430 bytes, initializes count, copies the 32-byte request key at leaf
+0x2c0, copies the value at leaf +0, and increments tree length. Those words are
reported literally; no invented semantic names are assigned to the contained
empty descriptors.

`0x3bcc840` constructs an iterator over the fresh one-row tree and calls
`0x3dd7580`. The latter allocates one 96-byte row. `0x39061a0` returns leaf/index0,
then exhausted on the next call. The collector copies the key32 and value64.
For this singleton, sorting and deduplication are skipped; its 32-byte flat
container descriptor is `[capacity=1, allocation, start=0, length=1]`. The shrink
helper `0x4562690` returns without change since capacity equals length.

The outer value has 72 bytes: leading qwords `[1,8,0,0,0]` followed by that nested
32-byte container descriptor. It is inserted at the actual vacant position via
`0x370b180` (tree) or `0x454e530` (flat). The flat row stride is 104 = key32+value72.
Success returns word 0x1a2. Physical outer balancing, representation conversion,
allocator failure and destructor behavior remain prerequisites; the source uses
an owned ordered map for the established logical behavior, not callback-supplied
entry or mutation outcomes.

## State and stop order

The wrapper reaches `0x44d8454` only for 0x1a2. It subtracts the amount from the
unsigned aggregate at owner+0x1c8, tests borrow, then stores the result. Therefore:

| Path | Request map at stop | Aggregate at stop |
| --- | --- | --- |
| Existing key | Existing value preserved | Unchanged; before unwrap at 0x44d8509 |
| Fresh key, amount exceeds aggregate | New nested request already inserted | Unchanged; before panic at 0x44d8524 |
| Fresh key, amount at most aggregate | New nested request inserted | Old aggregate minus amount |

The final source stop is after the aggregate store, before the lazy Once/logging
continuation. It does not invent a successful callback return or claim the
wrapper completed. A repeated request in the local state after a balance stop is
now a duplicate, but this is not a statement about retrying a real transaction.

## Validation

```
python3 research/work-items/RE-005-node115-bridge-request-mutation/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-bridge-request-mutation/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-bridge-request-mutation/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-bridge-request-mutation/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-bridge-request-mutation/Cargo.toml --all-targets -- -D warnings
```

Five Rust tests pass in both profiles. A 4,096-operation independent linear ledger
checks first-occurrence preservation and uses widened signed arithmetic for
balance stops. Fixtures cover changed duplicate payloads, partial mutation,
zero/equal/full-width amounts, address/word identity and all 32 byte positions,
including ignored padding. Strict Clippy and formatting pass. The static packet
checks 20 windows / 2,366 bytes / 520 instructions and rejects 34 semantic
corruptions after authenticating original digest and windows. These are static
and source-level checks, not executed native equivalence. Repository checks are
reported separately in the PR. All component gates remain false.

Source and evidence are independently authored under MIT; no unlicensed inferred
source has been copied.
