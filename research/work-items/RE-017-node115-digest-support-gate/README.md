# Digest candidate's two support gates

Partial RE-017 work on the Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This implements the selected normal support predicate behind the candidate
transition in #7048, starting after the native views have been materialized. It
does not establish signature authentication, live snapshot coherence, complete
tracker insertion, or trusted state roots.

## Existing work and new boundary

The first gate's strict weighted fold and checked overflow behavior were
reconstructed in #5459, `src/node115-staking-weight-comparison`; this source
reuses that implementation unchanged. #7048 observes that `0x28a9db0` calls
that gate and only on success constructs another set and calls `0x2738c80`.
#6459 already implements similar `count > fraction * total` arithmetic in a
different certificate path, but it first normalizes nonfinite fractions and
clamps finite values. The digest support helper takes its supplied binary64
value directly. `RE-017-node115-digest-producer-count-gate` already establishes
the same unclamped membership-count relation at a different producer
`0x5373e40`; this packet does not claim that relation as new. Its addition is
the actual two-key-family call composition and a reusable source implementation.

At `0x28a9e8a`, the caller materializes the first candidate key collection
through `0x22bbe80`: the flat path advances by 104 bytes and copies the first
32 bytes per row. At `0x28a9e9a`, `0x36c7f70` receives that collection and the
first context; false branches directly to false at `0x28a9eae`. Only on true,
`0x22bb880` materializes the second collection from the candidate's separate
96-byte rows, copying the first 20 bytes. `0x28a9f90..f99` passes the original
second and third caller contexts plus this collection to `0x2738c80`.

`0x2738c80` first compares the supplied binary64 with zero; both +0 and -0
return true without a key walk. Otherwise it iterates the supplied selected
20-byte keys with `0x2387b20` and searches each against the separate input tree
using all 20 bytes and imported `memcmp`. Each hit adds one with overflow
checking. The helper loads its descriptor pointer from `*RSI` at `0x2738cfe`; the total
is read from that descriptor at `(*RSI)+0x10` at `0x2738e36` rather
than recomputed from the tree. It returns the strict ordered comparison
`f64(matches) > fraction * f64(stored_total)`. Unordered comparisons, including
NaN and infinity multiplied by zero, are false. Negative fractions and
infinities are not normalized by this helper. There is no implicit overlap
between the 32-byte weighted set and the 20-byte count set.

`src/node115-digest-support-gate` supplies logical sorted sets and a weighted
map, calls the unchanged #5459 predicate, then performs the distinct raw
fraction count gate only on first-gate success. `stored_total` remains an
independent input word. Logical valid set/tree contents, the prior weighted
map materialization and its normal-return conditions, no alias mutation and
successful allocation and the normal binary64 floating-point environment are premises. It does not model native containers,
iterator ABI, overflow panic machinery or caller scheduling. The small numeric
helper is a host API for testing the native u64-to-f64 comparison; it does not
claim the caller can materialize every synthetic count. No full component gate
is advanced.

## Evidence and tests

`verify.py --target <pinned-ELF>` validates the full target digest, four FDEs
(825 decoded instructions), 34 selected instruction witnesses, the memcmp
relocation, the binary64 conversion constants at `0x451210` and `0x450170`
(2^52 and 2^84), and six counterfactual witness controls. Controls alter the retained
instruction statements after digest checks; they do not execute the captured
binary. The source tests cover distinct key families and the twentieth key byte,
first-gate rejection, stored-count mismatch, exact threshold equality, both
signed zeros, negative values, NaN and both infinities, u64-to-f64 rounding
near 2^53 and checked weight overflow. These are independently calculated
logical expectations, not native differential execution. Run debug/release
Rust tests, formatting and strict Clippy separately.
