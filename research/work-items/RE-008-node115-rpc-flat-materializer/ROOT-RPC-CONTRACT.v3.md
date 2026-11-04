# Node115 flat RPC search and all-or-nothing materialization — draft v3

Status: root's static value-contract proposal for independent review. No Rust,
mathematical reference or corpus execution is admitted by this document yet.
This is a substantive continuation of merged #2523, #2568 and #2620, not a new
claim for the already described collector/prefix relation.

## Identity and new scope

Target Linux x86-64 node115, 105896032 bytes, SHA256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Current main/base 05bc2de303c05525b71e7e257426e741bc66a390.
New semantic scope in previously censused full functions: flat search 0x57f5ee0..0x57f60cc (492 bytes), materializer
0x50f95f0..0x50f9720 (304 bytes). The prior RE-003-pr-integration-20261103/native-review.json already records
both exact extents/body hashes (materializer at lines6212–6217 and search at
lines11340–11345). That byte census is credited, not claimed again. The proposed
advance is the conditional search/materializer value relation and independently
authored source, not first byte coverage or reconstructed matching bytes. Retained lookup, wrapper, collector and batch builder are credited
context from their existing packets. No captured instructions were executed,
emulated or evaluated. Native disassembly reads an authenticated copy as data.

Evidence: rpc-flat-scout/flat.gnu.stdout, initial-audit.json and
rpc-flat-scout/detail/materializer.gnu.stdout plus detail/audit.json. The full
helper FDE is independently distinguished from its next-index upper bound.
GNU row syntax alone is not another native lineage or runtime oracle.

## Native domain and layout premises

The lookup receives a valid object L; the nonsentinel flat representation starts
at L+0x28. The helper's RDI points at four qwords: capacity c at +0, allocation
base at +8, head h at +16, live length n at +24. Each allocated row is 40 bytes:
a 32-byte key followed by one 8-byte stored handle. The helper receives a query
key pointer in RSI; the lookup's argument setup and the shared import are bound
by the scout audit.

Admitted logical domain:
- 0 <= n <= c; for c=0, n=h=0; for c>0, 0<=h<c.
- Live rows are physical positions (h+i) mod c for 0<=i<n.
- Live keys are nondecreasing under unsigned-byte lexicographic order.
- All referenced native allocations/objects/keys are valid, sized and stable;
  address arithmetic and native layout sizes do not overflow.
- A successful stored handle is nonzero and points at a valid live reference
  word/object. Reached reference increments/cleanup, locking, tracing, growth
  and diagnostics complete normally and preserve their stated caller data.
  For EVERY reached acquisition, LOCK INC/JLE must return normally: its
  pre-increment signed word must be nonnegative. This is per acquisition, not
  merely an initial-state check. For example, initial INT64_MAX passes once,
  wraps to INT64_MIN, and a repeated acquisition then reaches UD2. Any native
  correspondence for repeated returned handles must satisfy the premise for
  each increment. The handle value and its referenced count are distinct; a
  synthetic opaque handle word is never interpreted as that count.
- The materializer and collector operate under the observed calling convention
  on disjoint valid outputs, with no concurrent input/store mutation.
- Imported memcmp has its ordinary sign/equality contract over exactly 32 bytes.

These premises are not source-recovered constructor/eviction invariants or
concurrency/lifetime proofs. A host implementation may explicitly refuse invalid
headers, unsorted live keys and zero stored handles as safe input policies;
those refusals are not native error behavior. Values in authored tests are
opaque supplied words, never dereferenced as native addresses.

## Exact flat-search value relation

Let A be the live logical key sequence. For n=0 the return is tag1,index0.
Otherwise let a=min(n,c-h), b=n-a. When b=0, search all A. When b>0 the helper
first compares the physical row0 key, which is A[a], with the query:

- Equal: return tag0,index a immediately, without searching either segment.
- A[a] > query: search A[0:a], adding offset0.
- A[a] < query: search A[a:n], adding offset a.

This follows 0x57f5f16..0x57f5f5b and 0x57f601e..0x57f60b7.
Each selected nonempty segment uses a right-biased binary reduction: at
mid=base+floor(size/2), retain mid when key[mid]<=query, otherwise retain old
base, and reduce size by floor(size/2). The final comparison returns equal/tag0
or insertion/tag1, incrementing the candidate index only when the final candidate key is
less than the query. Each comparison is memcmp over 32 bytes; handle bytes are excluded.

Consequences for a sorted live sequence, to be independently proved:
- Outside the wrapped-seam equality exception, a hit returns the LAST equal
  key in the selected sequence (and thus the last global equal key).
- Wrapped-seam equality returns a specifically chosen matching index a,
  even if equal keys occur earlier in the tail or later in the head.
- On absence the insertion index is the count of live keys strictly below the
  query, in 0..=n. It is not a physical slot number.
- The caller requires tag bit0 clear and index<n, then selects physical
  (h+index) mod c with one conditional subtraction. It reads the handle at
  row+32 and performs the existing reference acquisition.

Example: logical [A,A,A], capacity4, head3, n3 gives a=1, b=2. Query A returns
logical index1, physical0. A contiguous layout for the same keys returns
logical index2. Replacing this with an unspecified standard-library duplicate
selection can therefore choose a different stored handle. This is a proposed
static consequence, not a target execution.

An independent mathematical expectation need not replay the binary loop:
apply the explicit wrapped-seam equality rule; otherwise enumerate all equal
logical keys and choose their final index, or count keys below an absent query.
This high-level relation is suitable for an independent oracle after review.
No emulator, instruction dispatcher, register/memory machine or captured helper
is to be used as that oracle.

## Collector context and materializer result

The existing collector 0x5b9cab0 advances through supplied 32-byte query keys,
retains the acquired handles in input order including repeated keys, and stops
on its first zero lookup result. Its separate failure byte is written1 on a
miss and otherwise left unchanged. Its ordinary output may retain a successful
prefix even on a later miss. Those findings are credited to #2523.

The newly inspected materializer:
- Writes zero to its local failure byte at 0x50f95fe.
- Copies the supplied three-word iterator/environment fields into a local
  descriptor and appends a pointer to that byte at 0x50f9603..0x50f9619.
- Calls the existing collector at 0x50f9628 and tests the failure byte against
  zero at 0x50f962d..0x50f9632.
- With zero failure, transfers all three vector-header words to the output
  at 0x50f968e..0x50f969c.
- With failure, writes only the first output qword as signed-minimum marker
  0x8000000000000000 at 0x50f9634..0x50f963e. It then walks the collected prefix,
  LOCK DEC on each stored handle's first qword; a zero decrement result requests
  drop through slot0x64e4cb8. After the loop it invokes the allocation-release-shaped helper iff its
  capacity is nonzero, requesting release with capacity*8 and slot0x64df4a0.
  Actual reclamation is an opaque helper effect, not established here.
- Returns the output address. The other output words on the failure route are
  not specified or cleared by these observed stores.
- Landing-pad cleanup, transitive drop/unwind behavior and failure/abort effects
  remain unclosed. The drop calls receive a pointer to the vector element;
  do not misstate this as passing the object pointer directly.

Therefore, under ordinary valid-helper premises, the MATERIALIZER's value result
is all-or-nothing: empty queries succeed with an empty sequence; if every query
finds a valid row, return all selected handles in query order; any miss returns
the failure marker and does not return its temporary prefix as a successful
vector. Prefix retention is an internal collector result, not the final
materializer output. No public network/RPC ABI or exact transaction type follows.

The previously documented batch builder #2620 treats this materializer marker
as a failure that discards its accumulated batch. That is credited context and
does not recover its opaque cost/other-store/ownership helpers.

## Intended independently authored operation and limits

Proposed component: a pure, dependency-free Rust operation over an explicitly
supplied immutable flat ring of 32-byte keys and opaque nonzero value words.
It should implement the real comparator and precise returned-index relation,
then perform actual supplied-key lookups and all-or-nothing materialization.
It must not receive mocked lookup answers or a callback that supplies results.

Chosen safe Rust types/Result or Option discriminants are host interfaces;
neither native ABI nor native reference counting is claimed. The library should
make invalid host input refusals explicit and should not execute keys, services,
signatures, filesystem operations, captured addresses or unlicensed code.
Transport policy belongs separately in the driver contract.

Scope exclusions: tree representation, store mutation/eviction/constructor
invariants, concurrent snapshots, locking/tracing/timing, exact allocator
capacity/growth/failure, native object lifetime/drop/unwind, network serialization,
domain key/value identities and full-node/runtime equivalence. Every full-scope
acceptance gate stays false. Source-byte equivalence is not a planned claim.

Before Rust: independently review this contract, authenticate the deciding bytes
and helper/import/FDE bindings, seal explicit mutation/witness obligations, qualify
a high-level reference and independent handcases, and freeze input/expectation
separation. Then build/run only the authored component and meaningful semantic
controls; never the captured node or repository evaluator suite.

