# Node #115 scale-zero caller: lookup, result and float handoff

Partial HL115-050, pinned to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are original ELF virtual addresses. No captured code is executed or
emulated. All component gates remain false.

## Prior scope and new join

Open PR #5071 owns the six asset-decimal scale bodies, including `0x3f10820`,
and explicitly leaves this caller open. Its source tool is not on this baseline.
The new source independently expresses that credited mathematical dependency to
connect real map lookups to the caller's zero result. It does not claim the leaf
as a new discovery or copy inferred source from that PR. The new evidence checks
the dependency against the original target as well as the previously unclosed
caller. The selected FDE is `0x3693bd0..0x36943ef` (2,079 bytes), correcting the
planning backlog's 2,623-byte estimate.

## Two lookups and argument identity

The fifth argument R8 and fourth argument RCX are full unsigned u64 keys into the
same sixth-argument map R9. RCX is looked up first, then R8. For a native tree,
keys begin at node+0x798, values have 176-byte stride, node count is +0x7f2 and
children +0x7f8. The second search restarts at the same root. For flat storage,
`0x4556410` searches sorted 184-byte rows (key8+value176), and caller wraparound
arithmetic maps logical index to the physical row. Exact equality and index bounds
are required. The owned source uses an ordered map for these established logical
lookups; native physical balancing, ring allocation and lifetime are premises.

Either missing key writes result qword 3 and result byte+8 = 9, then returns.
Only after **both** searches succeed does the caller require the first value's
u32 tag to equal 1. A different first tag writes result qword 2. The second value's
tag is not tested on this prefix; imposing a matching-tag requirement would be an
unsupported restriction.

The scaler receives first value+0x10 as numerator, second value+0x10 as divisor,
R8 (the **second key**) as metadata index, and the stack-supplied metadata owner.
First value+8 is saved separately for the later positive path. This does not
identify economic units or names for those words.

## Genuine zero and overflow zero

The credited scaler uses metadata bytes +0x48/+0x49 in 0x158-byte rows. In its
valid domain, `e = byte49-byte48` is in 0..19 and divisor is nonzero. Its result is
`ceil(numerator * 10^e / divisor)` if representable in u64, otherwise zero.
Metadata bounds, invalid powers and zero division are explicit source stop
boundaries rather than invented target error returns.

At `0x3693e1d..0x3693e20` the caller tests the returned u64. Zero goes straight to
`0x369434f`, which writes only output qword 2 before returning. It does not reach
the floating conversion. Genuine zero (`numerator=0, divisor=1, e=1`) and overflow
zero (`numerator=u64::MAX, divisor=1, e=1`) therefore produce the **same** native
result word; the caller retains no cause flag. This establishes control flow, not
that result 2 means an economic zero, absence, success or refusal in its consumer.
That result consumer remains open.

A positive result uses low/high u32 construction and subtraction of exact powers
2^52 / 2^84, followed by one rounded binary64 sum. This is unsigned-u64 to binary64
conversion, including values at and above 2^63. It then multiplies by the stored
binary64 constant 0.98 (`0x459588`). The source stops before the actual indirect
call at `0x3693e59`, whose slot `0x64e1890` resolves to `0x63efe40`. It neither
invents that helper's behavior nor continues through the later risk/rounding
helpers. Valid standard floating environment is a premise for this arithmetic.
The prefix mutates only its result output on early returns; it does not debit or
credit the input map.

## Validation

```
python3 research/work-items/RE-007-node115-scale-zero-caller/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-scale-zero-caller/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-scale-zero-caller/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-scale-zero-caller/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-scale-zero-caller/Cargo.toml --all-targets -- -D warnings
```

Six tests cover identical zero returns from distinct causes, full-width positive
conversion, both lookups before the first-tag gate, unchecked second tag, exact
value offsets, same-key lookup and metadata-index identity, and failure precedence.
An independent ceiling-inequality oracle checks 1,120 numerator/divisor/exponent
cases without repeating the implementation's quotient calculation. The original
static verifier checks 4 windows / 1,276 bytes / 331 instructions and rejects
24 field, branch, constant, lookup and helper corruptions. Debug/release tests,
formatting and strict Clippy pass. Repository checks are reported in the PR.
These tests establish bounded source/static observations, not native equivalence.
The source and packet are independently authored under MIT.
