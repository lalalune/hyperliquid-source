# Conditional HTTP header writer feasibility

This is independent manual reasoning from the complete retained instruction bodies and authenticated ELF data. It is not a source implementation, native execution, instruction evaluator, behavioral test result, or authoring approval. All addresses below are ELF virtual addresses in node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes. GNU symbol-neighbor labels are not recovered source names.

## Complete selected extents and credit

| Role | Full FDE extent | Bytes | Instructions | Raw body SHA-256 |
|---|---|---:|---:|---|
| Writer | 2e77070..2e7792e | 2238 | 489 | 0c097e71ffa7decf04240c24e5542f352c3a98a1fb36acc6ba2642da8aa46ad7 |
| Primary-map lookup | 2e81cc0..2e81e5e | 414 | 107 | 3aab1073f3650bd7c96e5c16ea2fa42706601402a4bfbbf622a3dde03a181538 |
| Spelling-map lookup | 2e81e60..2e8200e | 430 | 109 | df26226f0088385c0636c3bc1141e28ff5dea180964893fe3c29089dd625c0f8 |
| Shared name hash | 2e7f650..2e7f90d | 701 | 177 | e44354343651b25e2446a053178b7ba2b69e4757f690cb86e6b0877bf849a000 |
| Hash byte feed | 2e7f140..2e7f317 | 471 | 141 | 2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5f238c5096ed8b0 |
| Reserve wrapper | 2e8dbe0..2e8dc6e | 142 | 41 | d81e0ced0da02eb2e870d5bb09f9822e0e88b00c484643288e217093abbac4b9 |
| Allocation wrapper | 2e8daf0..2e8dbd9 | 233 | 74 | b7c396da0aac5565ba22b357ad3290bfe592828aebddced6d18f5a67e8b9893e |
| Credited ordinal leaf | 2e768f0..2e7690e | 30 | 7 | 4e0124c8aad3cec2bdca5ba0ec188a1470bee10b4f3c5f8bd1445c4dba17e12c |

Total: eight complete FDEs, 4659 bytes, 1145 decoded instructions. Each per-body JSON records exact raw FDE and CIE bytes, calls, RIP operands, body bytes and decoder identity. No selected FDE has an LSDA pointer. All selected body/FDE/CIE spans have no relocation overlay. The private data audit checks all 61001 RELA entries for selected spans. This is a validated local denominator, not a new exclusive byte-coverage claim.

The existing `RE-012-node115-header-name-lookup` packet already retains the whole writer, ordinal leaf and all81 names, and explicitly leaves complete encoder ownership/reconstruction open. Its source commit is `3a46c477333f0f797216d6ca11016bc87e10d979`; live commit-to-PR association returned an empty list, so no PR number is invented. `RE-003-pr-integration-20261103/native-review.json` also already censuses the writer's2238 bytes/489 rows. These receive prior credit. The potential contribution is a full conditional semantics/source operation, not republishing their two inline lookup sites. No unlicensed inferred source was read or copied.

Active PR2943 at head0900798da5c1c5137af6366d6f409b2fcf57d627 owns a separate sibling-hasher no-panic/LSDA question. Its exact head records bind4744980..4744b57 to the **same471-byte body hash** as2e7f140. That clone is existing open-work context, not new helper coverage. Its seeded wrapper4744490 has a different input sequence (raw bytes then255), so it is not the header-name hash. No new standalone feed/hasher source or panic-proof claim is proposed here. See SOURCE-SCOPE.md for the integration plan that avoids copying or reimplementing that actively owned generic feed operation.

## Names and the actual two lookups

A name record has a qword at+0x0. Zero selects a built-in ordinal from the byte at+0x8. Nonzero selects custom bytes at pointer+0x8/length+0x10. Built-in ordinals0..80 resolve through the81 relocated pointer cells at6459df8 and lengths at620800. Names are distinct tagged values: a custom byte string that happens to spell a built-in name does not compare equal to that built-in variant. Neither helper performs case folding.

Both lookups first read map+0x28 length. Zero immediately returns a not-found flag without hashing or dereferencing buckets. Only the flag and map pointer are active; the returned index storage can remain unspecified on not-found, especially the empty path. A future safe API must not expose that inactive index as a meaningful native result.

For a nonempty map they call the actual common hash at2e7f650, then use:

- bucket pointer map+0x48, bucket count map+0x50, u16 mask map+0x58;
- starting bucket `hash & mask`, wrapping a bucket index to0 when it reaches bucket count;
- each four-byte bucket is `(u16 row_index, u16 cached_hash)`;
- row_indexffff is empty;
- probe distance starts0 and increments with each advance;
- resident displacement is `(bucket_index - (cached_hash & mask)) & mask`, using the observed32-bit subtraction/mask;
- stop not-found on empty bucket or `probe_distance > resident_displacement`;
- require exact16-bit cached-hash equality before row/name comparison;
- require row_index < primary count, then compare name variant and either ordinal byte or equal-length bytes through imported `bcmp`.

The primary lookup's row stride is104, name at+0x40, pointer/ordinal+0x48, length+0x50. The spelling lookup's stride is96, name+0x38, pointer/ordinal+0x40, length+0x48. Both return the first matching probe. The byte comparison import is **bcmp**, symbol11/type6 at slot64df9f8, not memcmp. The required import contract is zero exactly when the two length-byte spans are equal, plus normal frame/noninterference behavior.

An admitted ordinary table domain must explicitly address termination and malformed states. A sufficient bounded safe-view domain is positive power-of-two bucket count at most65536, mask=count-1, at least one empty bucket, in-range resident row indices, stable rows/buckets/names, and canonical name variants/ordinals. This bounds a search by one bucket cycle. It is a proposed host restriction, not a proof of which states the native constructors produce. A nonempty table with bucket count0 reaches the explicit self-loop at2e81e20/2e81fd0. No safe refusal should be presented as that native behavior.

The full writer can be implemented using these real key comparisons and table searches. No callback, supplied found-index, precomputed query result, or external weight/status oracle is needed. If a future API instead abstracts valid maps to unique logical key groups, it must separately prove a concrete Robin-Hood table invariant sufficient for the abstraction; merely assuming that lookup returns the intended row would be circular.

## Shared hash closure, including its specialized byte-feed domain

At2e7f65a the map's firstDWORD equal2 selects the seeded ARX branch. Other DWORD values select the fast multiplicative branch. Each result is masked to15 bits at2e7f900.

For the fast branch let `P=0x100000001b3`, `C=0x1efac7090aef4a21`, `H0=0xcbf29ce484222325`, with arithmetic modulo2^64. `C=P^8 mod2^64`. Let `d=0` for built-in and1 for custom. First `h=(H0 xor d)*C`, corresponding to the eight little-endian bytes of that discriminant. A built-in ordinal `o` gives `h=(h xor o)*C`, corresponding to its eight-byte zero-extended value. A custom name instead folds every actual byte `b` in order using `h=(h xor b)*P`. The remainder-prefix/unrolled-eight loop consumes every byte once, including empty input. Finally return `h &0x7fff`. No string terminator or additional255 byte is fed.

The seeded branch initializes four words with two supplied u64 seeds and the exact constants at4522f0/4511c0. Memory state order is(v0,v2,v1,v3), with constants respectively736f6d6570736575,6c7967656e657261,646f72616e646f6d,7465646279746573. A round is the standard explicitly observed ARX sequence: add v1 to v0 and v3 to v2; rotate v1 by13 and xor v0; rotate v3 by16 and xor v2; rotate v0 by32; add v1 to v2 and v3 to v0; rotate v1 by17 and xor v2; rotate v3 by21 and xor v0; rotate v2 by32. These operations are defined modulo2^64, not signed arithmetic.

For each little-endian eight-byte word `w`, xor w into v3, apply one round, then xor w into v0. The first feed is exactly the eight-byte discriminant. The second is either the eight-byte built-in ordinal or the custom name bytes. The hash wrapper initializes pending count0; feeding exactly8 leaves it0. Therefore both calls from this wrapper enter feed with pending count0. The generic preexisting-partial-byte branch2e7f14e..232 is not needed to claim arbitrary streaming semantics. From count0, the full-word loop and final4/2/1 loads implement the exact supplied byte sequence, leaving a zero-extended little-endian tail and remainder count.

The final word is `(total_byte_count <<56) | tail`, modulo2^64. Process it with one round, xor it into v0, xor255 into v2, then perform three final rounds. Only the low15 bits of the four-word xor are returned. The last round is algebraically shortened by the compiler: the two occurrences of its final v0 cancel; low15(rol17(x)) equals low15(x>>47); low15(rol21(y)) equals low15(y>>43). The needed bits43..57 of rol16(v3) equal those of v3<<16, so its SHL16 at2e7f85d preserves the selected result. The remaining expression is low15(`v1_after_first_half>>47 xor v3_after_first_half>>43 xor v2_after_add xor (v2_after_add>>32)`), exactly the observed final instructions. This establishes the reduced computation's numerical relation without treating native bytes as an executable oracle.

No generic streaming hash API, original source identity, security property or producer seed distribution is claimed. This hash reasoning is contextual only. The proposed logical-map integration does not author this generic hash/feed operation; any later separate hash source would require a new ownership decision and independent pre-source evidence.

## Two value chains and writer composition

The first argument is the104-byte-row primary map; the second is the96-byte-row spelling map. The third is an existing output vector descriptor `(capacity,pointer,length)`. The low byte of the fourth argument enables ASCII title casing only for fallback names.

The outer loop walks **every physical primary row in stored order**, using its name as a fresh query into both maps. It does not deduplicate outer rows by name. A future safe policy that disallows duplicate primary keys must be stated, not silently attributed to the native loop. On a table that selects another equal primary row, the selected row's values are used even though the fallback name comes from the current outer row.

Each found primary row has a value at+0x18. The parity test of its firstbyte selects a single-value endpoint or a pair of extra-value head/tail indices at+0x8/+0x10. In the multi-value case the primary payload is yielded first, followed by extra rows. Extra primary-map rows have72-byte stride and payload at+0x20; their next option isDWORD at+0x10, with next index+0x18 when equal1. The tracked back endpoint ensures its last value is yielded once and terminates the cursor. Absent lookup gives an exhausted value cursor, so that outer row emits nothing.

The spelling map uses the same cursor shape, with96-byte primary rows,64-byte extra rows, payloads at+0x18/+0x20 and the same next-option offsets. Its primary value is used first. Each primary-value occurrence consumes at most one available spelling occurrence. Excess spelling occurrences are ignored after the primary-value cursor ends. If the spelling cursor is absent or exhausted, the writer uses the current outer row's canonical built-in table bytes or custom bytes. Therefore it is neither a Cartesian product nor an all-or-nothing name override for the whole group.

For a precise canonical safe domain, use firstbyte0/1 for primary chain variants and next-optionDWORD0/1 for extras; validate every reached index, finite chain and coherent last endpoint. The initial variant check is a low-bit test whereas the later invariant check is a zero/nonzero test. Arbitrary tag bytes must not be accepted by a source enum while claiming all malformed native states. Shared immutable extras can be permitted only with separately valid per-chain frontiers; allocation/ownership or original construction is not established by these reads.

Every chosen spelling byte string is copied verbatim. The capitalization flag does **not** modify stored spelling values. Fallback names with flag lowbyte0 are copied verbatim. With nonzero flag, the first byte and each byte following an emitted `-` are uppercased only if the current byte is ASCII a..z. All other bytes, including bytes outside ASCII, are unchanged. The loop's initial previous byte is `-`, and its previous-byte state becomes the emitted byte. It is not general Unicode or locale-aware title casing.

For each selected primary value, append exactly:

- nonempty value: `chosen_name || ": " || value || "\r\n"`;
- empty value: `chosen_name || ":\r\n"` (no space).

The existing output prefix is preserved. This body appends no final empty line, request/status line or frame terminator beyond each value's CRLF. Empty primary-map length returns before either lookup, output access or name interpretation. A future constructor may validate unused views eagerly as host policy, but must not claim that such refusal occurs natively on this empty path.

Manual discriminators, not executed tests: two primary values and one spelling use that spelling only on the first line; one primary value and two spellings emit only one line; empty values omit the space; capitalization affects fallback `x-test`→`X-Test` but leaves a supplied spelling unchanged; a missing self-lookup emits no line; duplicate outer names can repeat a selected value chain. These distinguish the proposed complete operation from simplified serializers.

## Allocation, copying, failure paths and limits

Each bulk append tests remaining capacity and calls2e8dbe0 only when insufficient. It computes checked used+additional, chooses max(required,2*capacity,minimum), and calls2e8daf0. For the writer's element size/alignment1, the minimum is8 and the allocation wrapper follows unaligned general allocation/reallocation endpoints; it returns the new pointer and reserve updates capacity/pointer. The wrapper does not prove actual allocator behavior. Both full wrappers were read, including overflow/failed-allocation routes to141e264.

The conditional successful-byte relation requires valid writable output storage, successful allocations/reallocations when requested, preservation of the old used prefix, valid disjoint source spans, exact memcpy copy behavior, stable live inputs/frame and ABI-preserved registers across ordinary helper returns. These are explicit external contracts, not inferred from names. The memcpy slot64df508 is an undefined symbol7 GLOB_DAT binding. Allocation slots64df580/588/590/480 bind635a790/635a7a0/63577f0/6355830; their implementation is opaque here. Panic slots64df620/730 bind1680cbf/1680e60. No unwind, OOM, capacity-overflow or malformed-index behavior is reconstructed.

The per-byte growth call at2e776cd binds141e080. Under the preceding bulk-reserve contract, it is unreachable during a nonempty title-case loop: before byte i, `old_length+i < old_length+name_length <= capacity`. It remains recorded as an excluded conditional path, not silently discarded or assumed to work.

All byte ranges and pointer/stride calculations must be valid and nonwrapping. Output must not alias names, values, map descriptors, buckets, rows or cursor state, including after growth. No request-entrypoint, network compatibility, header grammar/security validation, application field provenance, allocator effects, native ABI return shape or whole-HTTP reconstruction is claimed. Safe representation/refusal/resource policies require a separate contract and pre-source fixture gate.

## Feasibility verdict

The two lookup dependencies do not force an unbounded source reconstruction. The selected value dependency graph closes at a small hash/feed family, byte equality, copying and explicit successful-allocation contracts. A coherent contribution can reconstruct this **whole ordered header-byte append operation from actual supplied primary/spelling map data**. SOURCE-SCOPE.md chooses a unique-key logical-map integration domain and gives the concrete native table invariant needed to prove its real lookup correspondence. The complete native observations above retain duplicate behavior; that broader raw-state behavior is deliberately outside the proposed narrower source domain. A standalone hash clone, ordinal lookup, or callback-supplied lookup serializer is not proposed.

This is ready for independent native review and a parent pre-code scope decision, not direct Rust authoring. Remaining work is the independent peer, a precise chosen host representation/validation policy, independent literal boundary expectations, reproducible static controls and an input-only implementation qualification. Live ownership remains bounded by the recorded searches/head scopes and must be refreshed before admission/publication.
