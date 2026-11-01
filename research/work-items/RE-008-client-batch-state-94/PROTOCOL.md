# Frozen input-only comparison protocol

This is a test transport for independently authored safe code, not a target wire
format. `corpus.py` alone derives expectations before any new Rust or driver.
The future client receives only `inputs.tsv.gz`, decompressed by its parent.
Each line is `C000000<TAB>lowercase_hex_frame`; IDs are opaque sequential labels.
Names and expectations remain in separate parent-only files. No expected result,
precomputed block digest, validity flag or selected verifier error is an input.
Transaction and QC claimed hashes are actual fields that the operation checks.

All integers are unsigned little endian; u8 is one byte, u32 four, u64 eight.
`vec(X)` is u32 count then that many X values. There is no alignment padding.
The decoder rejects truncation, trailing bytes, invalid options, out-of-order or
duplicate history/stake keys, and lengths that cannot fit the remaining frame.
Counts do not authorize an allocation before remaining-frame bounds are checked.

| Structure | Bytes, in order |
|---|---|
| QC scalar | hardfork version u64, hardfork start u64, round u64, hash32 |
| QC | QC scalar, vec(vote) |
| vote | signer20, signature72 |
| TC | round u64, vec(timeout) |
| timeout | QC, round u64, signer20, signature72 |
| unsigned timed block | round u64, proposer20, three raw time u32s, vec(hash32), QC, option TC |
| timed block | unsigned timed block, signature72 |
| option | u8 0 absent or 1 followed by value |
| item | timed block, vec(tx), three copied time u32s, option proof |
| tx | claimed hash32, u32 byte length, actual bytes |
| proof | child timed block, QC |
| history | base u64, hardfork version/start u64/u64, estimated-until u64, vec(snapshot) |
| snapshot | key round u64, vec(stake) |
| stake | validator20, weight u64 |

Frame starts ASCII `CB1`, mode u8, history. Mode0 continues start round u64,
vec(item). Mode1 continues last_received u64, confirmed u64, vec(initial pending),
close_after u64, vec(incoming items). Mode1 is a sequence of direct buffer calls,
including calls after previous recoverable errors. It does not model an outer
poll that may reset or stop. Initial state is explicit; fixtures use valid
value layouts. Close_after limits the total accepted prefix at the abstract sink,
not a signature validity input. Every attempted send returns accepted while the
accepted count is smaller; the next attempt returns closed with its item.

## Deterministic fixture authenticator

This is deliberately an explicit non-cryptographic-oracle test boundary, built
only from input values. Let K be ordinary Keccak256 from the credited mathematical
provider, and encode structures exactly as above. Native block preimages and
signatures are not predicted by these fixtures. Conditional batch outcomes use
the declared boundary contract; the empty-stake counterexample uses no boundary
calls at all. No production authenticator is supplied by this contribution.

Expected proposer is the smallest eligible validator by lexicographic20 bytes;
empty eligibility returns a fixture Authentication error with unknown target tag.
For domain ASCII D, message M and signer A, fixture signature is
`A || K(D || M || A) || 20 zero bytes`. Recover succeeds exactly when all72 bytes
match that form and returns A; admission still checks claimed-address equality,
membership, quorum, hardfork and round rules itself.

- QC D=`fixture-qc-v1`, M=QC scalar; the signer is explicit, never inferred from
  an item ID or expected output.
- Timeout D=`fixture-timeout-v1`, M=QC scalar followed by timeout round u64.
- Block D=`fixture-block-sign-v1`, M=unsigned timed block. This makes every signed
  time word observable at the required extended signer method. The baseline
  untimed block-signer method must not be used by the new module's adapter.
- Block digest is `K("fixture-block-v1" || unsigned timed block)`. This is a
  fixture function, explicitly not node94's consensus preimage. It is stable on
  equal complete values and records every invocation, including repeats.

The expected model implements the baseline admission scalar rules independently.
It does not accept preselected validity outcomes. Native interpretation remains
conditional on a real authenticator satisfying the corresponding native helper
contract; the fixture signatures make no secp256k1 claim. The corpus has no
competing failing TC children or parallel cancellation case. Successful and
single-child TC cases avoid the inherited ambiguous multi-error precedence.

## Observations and output

An error status is kind u8, tag u8, payload length u32, payload bytes. Success is
just u8 zero. Kind1 is local batch error, 2 existing admission error, 3 existing
safe fatal-policy result, 4 outer buffer error. The tag uses the known low byte;
fixture Authentication with unknown native tag uses255. Fatal tags0/1 mean stake
overflow/newer-hardfork with quorum; they are not native ordinary returns.
Only active payloads are compared: local21 two u64s,22 two hashes,23 one claimed
hash; admission0 four hardfork u64s,12 proposed20+expected20,15 supplied/expected
u64s,40 requested round; outer44 supplied QC round; outer42 the exact27-byte
text. Other modeled variants have no active payload. Formatted native strings,
inactive copied bytes, allocation addresses and padding are outside this format.

A trace entry is code u8, round u64, K(method input)32. Codes:1 proposer,
2 QC recovery,3 timeout recovery,4 timed-block recovery,5 block digest. Inputs:

- proposer: round u64 and vec(eligible20) in sorted order;
- QC: QC scalar and signature72;
- timeout: QC scalar, round u64, signature72;
- timed block recovery: full timed block;
- block digest: unsigned timed block.

These trace entries observe safe authenticator calls, not internal target
instruction counts. They constrain composition order and repeated digest calls;
clocks, logs, mutex events and allocations are intentionally not API observations.
The existing dependency's internal authentication ordering is credited, not newly
asserted exact for ambiguous TC parallel errors.

An item fingerprint is K(its full item encoding), a comparison convenience only.
A buffer snapshot is last_received u64, confirmed u64, vec(pending fingerprint32).
A step result is status, snapshot, vec(all accepted fingerprint32 so far).
A sink event is accepted u8, last_received u64, confirmed u64, pending_length u64,
item fingerprint32. The sink receives an immutable scalar BufferView and cannot
mutate buffer state; observing it is a safe adapter, not a native ABI claim.

Mode0 output is status then vec(trace entry). Mode1 output is vec(step result),
vec(sink event), vec(trace entry). Future client prints opaque ID, tab, hex output.
Parent compares exact bytes against `expected.tsv.gz`; only the parent reads
expected files. Identical mutable state histories and accepted prefixes matter,
not just a final success count. Traces retain the second last-block digest and
mismatch-only second child digest. Frozen cases metadata records why each case
exists and its active outcome; input has neither those names nor outcomes.

## Safe input domain and future implementation checks

Before semantic work, check native spans for all supplied pending/incoming
items: item count*32, tx rows*40, tx byte count, block hash count*32, QC vote
count*96, TC timeout count*184 and all nested proof values fit `isize::MAX`
without multiplication/addition wrap. Each supplied object is valid even if a
later semantic branch would not read it. These safe admission failures are new
API results, outside the native valid-memory theorem. Buffer append uses a
fallible reserve before publishing semantic state; refusal leaves state alone.
Existing verifier allocations and external callback panics are not promised to
be recoverable. Later implementation-only length probes may test these admission
helpers without allocating gigantic slices; they must be labeled safe-source
policy, not captured executions or additional target-derived fixtures.
