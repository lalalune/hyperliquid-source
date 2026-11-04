# Node #115 nonce text values

This independently authored `no_std` + `alloc` library decodes a canonical
unsigned-integer list prefix and calls the existing `node115-nonce-ring`
strict ordering predicate. The only dependency is that real local crate.
It supplies the missing text-to-values operation for a future importer;
it is not an integrated node or a public nonce-policy implementation.

The sole target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The basis is [the provider packet](../../research/work-items/RE-001-node115-nonce-text-provider/README.md):
provider `0x1e29f50..0x1e2a28d`, called by ordering wrapper
`0x2923da0..0x2923ee1`. Credit PR #1396 for that native proof, PR #1003 for
the native ordering relation and PR #1694 for its existing Rust implementation.
This component claims zero new recovered native bytes.

`decode_nonce_text(input, mode, depth)` takes arbitrary immutable bytes and
raw mode/depth bytes. Its successful grammar is:

```text
W '[' W (I (W ',' W I)*)? W ']'
W = zero or more bytes 09, 0a, 0d, 20
I = '0' or [1-9][0-9]*, with value <= u64::MAX
```

It preserves values and requires strict increase only after the complete list
has parsed. Thus `[2,1]` reports the ordering branch while `[2,1,]` reports
non-admission. Consumption stops immediately after `]`, leaving any trailing
bytes. Only success exposes consumption. Opening recognition precedes depth
checks: mode zero distinguishes initial depths zero and one; every nonzero
mode bypasses depth. No native parser object is accepted or mutated.

`NotAdmitted` is a logical admission policy. It does not assert normal return,
termination, cursor identity or diagnostic identity for opaque native numeric
and error helpers. `DepthZero` identifies the observed failure call, without
claiming it cannot return. `OrderingInvariant` observes the complete-list
failure route without executing a trap. The outer two-field caller, floating
conversion, error payloads, ABI, unwinding and live nonce policy remain outside
this reconstruction.

Successful correspondence is conditional on the provider proof's valid-storage,
ordinary-flow, helper-preservation and native allocation premises, plus the
source passing its capacity checks and actual fallible reservations. Source
host resource failure has separate outcomes. Initialized length is limited to
`2^59` words and `isize::MAX` bytes. Source allocation growth is not a native
capacity model. The private safe adapter passes exactly N initialized values
with capacity=count=N and head=0 to the existing unsafe ring function; it never
passes uninitialized spare capacity.

The input-only `nonce-text-client` reads ASCII lines:

```text
case_id<TAB>mode_decimal<TAB>depth_decimal<TAB>input_hex_or_dash
```

IDs contain ASCII letters, digits, hyphen or underscore. Decimal fields are
unsigned bytes; hex accepts either case and `-` means empty input. Lines end
with LF or CRLF. Malformed transport exits 2 independently of parser outcomes.
The client uses stdin/stdout only and never reads expected results. Its host
I/O allocations are outside the library's fallible parser-storage contract.

Expected values were frozen independently before this source existed.
The 55-row arithmetic test table is a mechanical projection of that frozen
resource table; it tests the pure capacity policy without enormous allocations.
Actual host allocation failure is not exercised or claimed as native OOM.
Build and executable comparison results belong in the accompanying evidence
packet; a cross-built Linux rlib does not establish Linux execution or identity.
