# Node #115 flat margin range

This dependency-free `no_std` library selects the complete live prefix of a
borrowed flat margin table whose unsigned key is at most the query. It returns
the original two physical row slices and the final included row, including its
logical/physical indices, key, offset word and divisor byte. It performs no
margin arithmetic.

The selected native scope is node #115
`0x3cd80d0..0x3cd8292` plus `0x4550ee0..0x4550fc4`, under the flat,
unbounded-lower/included-upper path. Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The [evidence packet](../../research/work-items/RE-007-node115-margin-range/)
records the conditional proof and actual qualification status.

`Ring::new(rows, head, live)` validates bounds before ordering only the live
logical keys. Empty backing requires head/live zero; nonempty backing requires
head below capacity even for a zero live count. Keys are unsigned little-endian
u64 words at row offset zero. Duplicate keys are valid, including a run crossing
the wrap seam; inactive rows need no ordering. All other row bytes are preserved.

`Ring::through(exposure)` uses an upper-bound binary search. The selected row is
the last logical key less than or equal to the full-u64 exposure. When no row is
included, both slices are `rows[0..0]` and the selected row is `None`. Otherwise
the first slice starts at head and the second at backing index zero. Projection
reads the offset u64 at byte 24 and divisor byte at 32. Divisor zero is allowed.
The library allocates nothing, mutates nothing and has no driver-size caps.

Bounds/Order errors, indices and `None` are safe API observations, not native
error variants or a recovered return ABI. Native correspondence requires valid
stable flat storage, nonwrapping spans and the stated call/frame premises. Tree
representation, constructors, financial units, downstream diagnostics, ownership
effects and higher position behavior remain outside this operation. Existing
margin arithmetic work is credited separately; this component does not depend
on or duplicate that implementation.

The `margin-range` is an input-only qualification transport. It accepts
zero arguments and ASCII LF-terminated records with five tab-separated fields:
`id`, `head`, `live`, `exposure`, `rows`. IDs are unique, 1–64 ASCII alphanumeric,
underscore or hyphen characters. Numbers are canonical unsigned decimal; rows
are comma-separated lowercase 80-digit hex strings or `-` for empty backing.
Limits are 16 MiB input, 50,000 records and 4,096 physical rows per record.

Success has twelve tab-separated fields: ID, `ok`, included count, first/second
length, selected logical/physical indices, key, offset, divisor, first/second
row hex. Missing selection uses five `-` fields; empty slices use `-`. View
refusals are `id`, `err`, `bounds` or `order`. Every record is parsed and all
output buffered before stdout is written. Invalid syntax/arguments/input-read
failure exits 2 without stdout; output I/O failure exits 1 and may leave partial
output. Host allocation failure is not a recovered native outcome.

This source was authored from the host contract and static evidence without
reading the frozen generator, corpus or expected outputs. Initial source freeze
precedes compilation. Build/comparison results are pending at this historical
source snapshot; no captured code, target-runtime equivalence or completed
component gate is claimed. New code uses MIT; no inferred unlicensed source
was copied.
