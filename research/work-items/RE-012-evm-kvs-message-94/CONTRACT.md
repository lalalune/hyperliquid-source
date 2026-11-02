# EVM KVS message decoder contract

RE-012 / transport and storage. Source base
`536bee4033075a1d18be048de249c1d6bbc2c779`; node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Linked ELF VAs. This contract precedes the independent Rust implementation.

The caller at `0x2264f84` supplies a complete frame payload to wrapper
`0x28bcd70..0x28bd73d`. The wrapper's ordinary path initializes logical mode
1 and charges 4, then decodes a variable-width u32 selector. Selector 0 is a
sequence; selector 1 is a unit. Every selector >=2 is an UnexpectedVariant
for the target type string `EvmKvsMsg`, maximum 1. Special caller values
`2^63+1` and `2^63+2` do not establish additional wire selectors.

The sequence helper `0x2891ff0` charges 8 for its u64 element count, then
checks multiplication and addition of a reservation `32 * count`. Each
original element refunds 32 before decoding. Element helper `0x288ede0`
reads two byte arrays, in order, through `0x2891c30`. Each array charges 8
for its u64 length, charges that length, then rejects a length greater than
remaining input with CollectionTooLong (target kind 1), before consuming any
payload bytes. Otherwise it retains every raw byte. Elements and their order
are preserved, including duplicate or empty first arrays; no map operation
or deduplication occurs. The target converts both arrays to boxed slices.

A complete sequence charges `12 + sum(16 + first_len + second_len)`, but must
also pass the peak reservation check. An empty sequence charges 12. The unit
charges 4. Overflow leaves the previous charge unchanged; exceeding the limit
retains the increment. Successful parsing accepts a suffix and reports actual
consumed/remaining bytes. Failures preserve actual cursor and logical charge;
the native wrapper's separate diagnostic consumed field is zero on errors.

The u32 fast path is selected when remaining input is greater than 4; invalid
FD/FE/FF markers remain unread there and report expected code 2, found 3/4/12.
The slow path consumes such a marker. Ordinary u64 uses the fast path above
8 bytes: FE/FF remain unread and report expected code 2; the slow Reader
consumes them and reports expected code 3. FB/FC/FD extension widths, shortage
handling and nonminimal encodings match the established varint primitives.

Implement the wire/value projection in the existing independently authored
Rust component, without a new workspace or dependencies. Public names Batch
and End express the observed repeated-row versus unit distinction; native
layout, original enum names, allocation/growth identity and TLS instrumentation
are outside this implementation. Preserve raw arrays and row order. Parsing
is not permission to trust or write the values to a database. No filesystem,
network I/O, state-root validation or node/Docker acceptance is implemented by
this decoder.

## Separate cumulative receive-size guard

This section precedes implementation of the caller's cumulative size guard.
The zeroed store at `0x226349a` initializes the u64 total at state `+0x568`.
The success loop returns to `0x22634a2`, preserving that total. For each legal
pair, `0x2266a5e..0x2266a88` adds the two byte lengths with saturation and
adds that result to the total with saturation, storing it immediately.
Empty arrays and duplicate keys still contribute their lengths; a null first
pointer denotes the iterator's end and is not an empty boxed array.

After all rows have been placed in the temporary write batch, the caller tests
`(total >> 11) > 0x2e90edc` at `0x2266b3e..0x2266b50`. The first rejected
total is `(0x2e90edc + 1) * 2048 = 100,000,000,000` raw bytes. The comparison
precedes the database apply call at `0x2266d8a`. Rejection retains the updated
total, drops the pending batch and emits `RocksDb too large`. The unit message
bypasses this per-batch guard. Frame headers, encoded integer prefixes and
logical decoder reservations are not counted in this cumulative total.

Expose a separate default-zero `TransferSize` value with read-only total and
`account_batch(&[Pair])`. It saturates all row byte lengths into its total,
then rejects totals greater than or equal to the exclusive limit. On error,
keep the new total and require the caller to abandon this transfer. This
pure guard must not claim to perform the target's temporary-batch allocation,
RocksDB apply, filesystem cleanup, state validation or network loop.
