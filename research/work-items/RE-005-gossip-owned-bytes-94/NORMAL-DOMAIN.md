# Bounded ordinary-return wire/state relation

Root disposition accepts this scope before any new Rust or independent wire
oracle. Target node94 SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The new normal relation covers primary `0x466dc10..0x466dcf4` (228 bytes /
68 rows), specialized collection `0x4589a30..0x4589b2b` (251 / 78), and the
byte validator `0x157a200..0x157a3f7` (503 / 143). These are 982 bytes /
289 rows. Existing length-wrapper/Reader/error-helper semantics are separately
credited context, not new recovery. The supplied u8-function address is unused
by the specialized collection body; there is no per-element callback claim.

## Memory and fixed-helper premises

The input is an immutable valid nonwrapping slice of at most `isize::MAX`
bytes. Native input, output, decoder state, temporary stack, code and allocated
storage do not alias improperly and are not concurrently mutated. Calls return
ordinarily. The logical state retains the complete raw mode QWORD, limit and
counter; no original configuration type or constructor is assigned.

For a positive admitted length N, the real native allocation helper must return
a valid disjoint writable N-byte allocation or leave the ordinary-return domain.
The selected dynamic `memcpy` copies exactly N disjoint bytes and preserves live
reader/output state. Its N=0 invocation makes no memory access, including with
the helper's dangling nonnull destination 1. The release helper returns normally,
accepts the genuine allocated buffer/size and preserves live reader, output and
error metadata. These are explicit functional premises, not newly recovered
contracts for every allocator/TLS/OS state.

The original 7,906-byte allocation implementation, TLS-sensitive release helper
and its `0x54c7550` tail, unwind state, allocation addresses and original ABI
remain open. No stub, mock allocator or invented captured helper will be linked.
New Rust must use its real standard allocation/copy facilities and an
independently authored byte grammar validator. Any chosen allocation refusal in
new source must be reported separately; it is not an observed native OOM result.

## Defined observations

Observe the raw logical result tag and only fields actually active for that tag,
the full final counter, ordered counter stores (including stores of the same
value), consumed byte count, complete unread suffix and successful owned bytes.
For validation error, observe the first invalid sequence's start offset and
optional error length, plus the ordered request to release N bytes before result
publication. Physical allocator/cache state, native addresses and result padding
are excluded; the safe representation does not assert the native nominal type.

The validator's native error record writes QWORD index at +8, BYTE option tag at
+16 and BYTE option payload at +17. The remaining six bytes of that copied
16-byte metadata span are not defined by the validator. When the option tag is
zero, its payload byte can be stale, including after instructions that modify
BL in the EE/EF and F1..F3 paths. The logical Option projection must exclude that
inactive payload and all padding, rather than claiming complete raw result
memory equality. On success native storage contains capacity N, allocated
pointer and length N; the safe value projection exposes owned byte content and
length, without allocator-address or physical capacity equivalence.

## Capacity and exceptional branch exclusion

Collection first checks N against remaining input before its signed-length
allocation test. Since remaining input is at most `isize::MAX`, availability
success implies N<=remaining<=isize::MAX. Its successful native record stores
capacity=N and length=N. Therefore the outer NEG/JO arm, which requires capacity
exactly 2^63, is unreachable after a genuine ordinary successful collection.
The exact branch remains in the retained native export; no borrowed-type or
other source-enum interpretation is inferred from it. The final exceptional
landing pad is retained separately and excluded from ordinary-return behavior.

No mapped/built/behavior/identity component gate advances from this bounded
relation. It does not establish whole gossip response grammar, caller type
ownership, original source/compiler, captured-machine-code identity or networking.
