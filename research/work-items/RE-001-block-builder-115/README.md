# RE-001: pin node #115 RocksDB BlockBuilder at 0x6129a00..0x612a4f2 with its hash-index annex and the rocksdb::Hash leaf

Bounded question: how does node #115's embedded RocksDB build a
data block — the exact entry encoding, restart rule, size estimate,
finish trailer and reset state of `BlockBuilder`, the behaviour of
its `DataBlockHashIndexBuilder` annex, and the byte rule of the
`rocksdb::Hash` leaf the annex calls?

Target: node #115 work binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound to provenance/artifacts.json for node #115).

Function names below are the RE-002 vendor-census labels for these
addresses, except the two local helpers at 0x612ce10 and 0x612ce90,
which have no census record and are named by this packet. The
census records identification and rebuild byte similarity only;
the byte rules, state rules and caller census here are this
packet's own, read from the target bodies and checked by emulation
(see Validation).

## What is pinned

Object layout (offsets from `this`): +0x00 int32
restart_interval_, +0x04 uint8 use_delta_encoding_, +0x05 uint8
use_value_delta_encoding_, +0x08 std::string buffer_, +0x28
std::vector<uint32> restarts_, +0x40 uint64 running finished-size
estimate (the bodies keep it equal to buffer_.size() +
4*len(restarts_) + 4), +0x48 int32 counter_, +0x4c uint8
finished_, +0x50 std::string last_key_, and the annex at +0x70:
+0x70 double per-entry bucket increment, +0x78 double bucket
accumulator, +0x80 uint8 enabled flag, +0x88 entries vector of
8-byte records {uint32 hash, uint8 restart_index, 3 pad bytes}.

Constructor (0x6129a00, 267 bytes): stores the interval and the
two encoding flags, initialises restarts_ to [0], the estimate to
8, counter_ and finished_ to 0, and fixes the annex increment:
-1.0 when the index-type argument is not 1
(kDataBlockBinaryAndHash); for type 1 it is 1.0/ratio when
ratio > 0, 4/3 when ratio <= 0, and NaN when ratio is NaN (the
NaN case takes the division path, it is not special-cased).

Add (0x612a1b0, 834 bytes): when counter_ >= restart_interval_
the entry starts a restart: (uint32)buffer_.size() is pushed onto
restarts_, the estimate grows by 4, counter_ resets to 0 and
shared is 0. Otherwise, with delta encoding on, shared is the
longest common prefix of last_key_ and the key. The header is
varint32(shared), varint32(non_shared), and — only when value
delta encoding is off — varint32((uint32)value.size()). Then
key[shared:] is appended, then the value bytes: the full value,
except when value delta encoding is on and shared > 0, when the
caller-supplied value_delta slice is appended verbatim instead
(its data pointer and size are read with no null check). Before
the header is written, a live annex receives the key minus its
last 8 bytes (the internal-key tag) with
restart_index = len(restarts_) - 1. After the appends, counter_
increments, the estimate grows by the bytes appended, and with
delta encoding on last_key_ becomes the key. Every append goes
through the string append path that throws std::length_error
("basic_string::append", literal at 0x4474d2) when the remaining
capacity is smaller than the piece.

Finish (0x6129c10, 376 bytes): appends every restart offset as
little-endian uint32; then, only when the annex is enabled and
estimate + num_buckets + 2 <= 0x10000, appends the annex block
through the annex Finish; then stores the trailer word
num_restarts, with the top bit 0x80000000 set exactly when the
annex block was appended (the trailer helper at 0x612ce90, 22
bytes, sets the bit only for flag == 1); then sets finished_ to
1. The Finish body contains no finished_ guard, so a second
Finish appends the restart array and trailer a second time.

Reset (0x6129f60, 160 bytes): clears buffer_, truncates restarts_
to one element (growing it back to one through the helper at
0x6129d90 when it is empty), restores the estimate to 8, zeroes
counter_ and finished_, clears last_key_, and tail-jumps to the
annex reset helper (0x612ce10, 31 bytes) only when the annex is
enabled; the helper zeroes the accumulator, sets enabled to 1
and clears the entries vector.

EstimateSizeAfterKV (0x6129b10, 253 bytes) is an estimator, not
an exact size: estimate field + key.size + (num_buckets + 2 when
the annex is enabled) + a value term + a header allowance. The
value term is value.size, halved (value >> 1) only in the delta,
non-restart case; the header allowance is 8 + varint32len(key) +
varint32len(value) when a restart is imminent, 4 + both varint
lengths when delta encoding is off, and in the remaining delta
case 4 + varint32len(key), with varint32len(value) added as well
unless the stored use_value_delta_encoding byte is exactly 1
(a nonzero byte other than 1 takes the longer allowance).

Annex Add (0x612ca80, 455 bytes): when restart_index > 0xfd
(253) the body sets enabled to 0 and records nothing — and the
disable is sticky, because Reset reaches the annex reset helper
only while enabled is still set, so a disabled annex is never
re-enabled by Reset. Otherwise it appends the record
{Hash(user_key, 0x18d), (uint8)restart_index} and adds the
increment to the accumulator by repeated addition (six additions
of 4/3 give 7.999999999999999, not 8.0).

Annex Finish (0x612cc80, 396 bytes): builds a byte array of
num_buckets bytes initialised to 0xff; for each entry in order,
slot = hash % num_buckets: an empty slot takes the entry's
restart_index byte, a slot already holding that byte keeps it,
and a slot holding a different byte is demoted to 0xfe. The
array is appended to the output string, followed by num_buckets
as little-endian uint16.

num_buckets = (uint16)((int32)accumulator | 1), computed
identically at the Finish gate, in the annex Finish and in
EstimateSizeAfterKV; the double-to-int32 conversion is
cvttsd2si, so a NaN or out-of-range accumulator converts to
0x80000000 and yields 1 bucket.

rocksdb::Hash leaf (0x61c34a0, 133 bytes): m = 0xc6a4a793;
h = seed ^ ((uint32)len * m); each full 4-byte group:
h = (h + LE32(group)) * m, then h ^= h >> 16; the tail bytes are
added sign-extended (movsx from int8) — a 3-byte tail adds
s8(b2) << 16, then s8(b1) << 8, then s8(b0), a 2-byte tail the
last two, a 1-byte tail the last one — and the final mix
h *= m, h ^= h >> 24 runs only when the tail length is nonzero,
so an input whose length is a multiple of 4 skips it. All
arithmetic is uint32.

Relations: the Hash body is cited but explicitly not read by
earlier packets — RE-001-hash-find-insert-115 records it as
unknown "by contract, not read", and RE-014-batch-lookup cites
it only with seed 0xbc9f1d34; this packet pins the body itself
(the annex uses seed 0x18d). EncodeVarint32 at 0x61bd410 is
identified by the vendor census but pinned by no merged packet;
it is not a body here, because Add's header varints are emitted
inline in the pinned Add body. BlockBuilder::AddWithLastKey at
0x612a500 (743 bytes) is a sibling of Add that shares the annex
Add call; only its call site is recorded here.

## Census (whole-file scan, reproduced by census.py)

- Constructor 0x6129a00: 16 direct calls, 0 tail jumps, 0 stored
  qwords, 0 RELATIVE addends. Sites include
  BlockBasedTableBuilder::Rep::Rep, CreateIndexBuilder,
  MetaIndexBuilder and PropertyBlockBuilder constructors.
- EstimateSizeAfterKV 0x6129b10: exactly 1 direct call in the
  whole binary, from FlushBlockBySizePolicy::Update
  (0x613bafc). No other caller exists.
- Finish 0x6129c10: 11 direct calls and 3 tail jumps
  (PartitionedFilterBlockBuilder::Finish, MetaIndexBuilder::
  Finish, PropertyBlockBuilder::Finish), 0 stored qwords,
  0 RELATIVE addends.
- Reset 0x6129f60: 0 direct calls and exactly 1 tail jump, from
  the 26-byte body at 0x612a000 immediately after Reset itself.
- Add 0x612a1b0: 15 direct calls, 0 tail jumps, including
  BlockBasedTableBuilder::Add (0x60f0b39) and the index and
  filter builders' Add/Finish paths.
- Annex Add 0x612ca80: exactly 2 direct calls — BlockBuilder::Add
  (0x612a31b) and BlockBuilder::AddWithLastKey (0x612a66c).
- Annex Finish 0x612cc80: exactly 1 direct call, inside
  BlockBuilder::Finish (0x6129d3b).
- Annex reset helper 0x612ce10: 0 direct calls, exactly 1 tail
  jump, inside BlockBuilder::Reset (0x6129fcc).
- Trailer helper 0x612ce90: exactly 1 direct call, inside
  BlockBuilder::Finish (0x6129c9f).
- rocksdb::Hash 0x61c34a0: 26 direct calls, 0 tail jumps,
  including the annex Add site (0x612caca) and
  DataBlockHashIndex::Lookup (0x612ce6c); the other sites are
  recorded as sites only.
- Internal transfers: the ten bodies call the string/vector
  append and replace paths, the two local vector helpers at
  0x6129d90 and 0x612a020, the annex bodies above, and the PLT
  stubs for memcpy, memmove, memset, operator new/delete,
  __throw_length_error and __stack_chk_fail. No indirect calls
  or indirect tail jumps out of any of the ten bodies.

## Validation

tools/block_builder_115.py transcribes the ten bodies.
tests/test_block_builder_115.py runs 5,092 pure-model checks
(layout invariants, header encodings, restart and delta paths,
the estimator branches, the annex cap and sticky disable, the
bucket demotion rule and the Hash tail rule). Separately, the
lane emulated all ten bodies under Unicorn against the model on
2,183 differential cases (randomised Hash vectors, varint and
trailer units, randomised estimator states, and twelve full
builder lifecycles including delta, value-delta, restart,
annex-cap and sticky-disable paths, plus Reset with an empty
restarts vector), 0 mismatches; the emulation hooks the
memcpy/memmove PLT stubs that the local string/vector helpers
call.

## Evidence format

- ctor.txt / estimate.txt / finish.txt / reset.txt / add.txt /
  hash_add.txt / hash_finish.txt / hash_reset.txt / trailer.txt
  / hash.txt: verbatim objdump excerpts of the ten bodies (FDE
  ranges in frames.txt), regenerated by export_excerpts.py and
  re-checked byte-for-byte by verify.py against a fresh objdump
  run and the raw binary.
- callers.tsv: every confirmed direct call and tail-jump site
  with its smallest enclosing FDE and a context note.
- relocations.txt: intentionally empty — the census finds no
  stored qwords and no RELATIVE addends for any target.
- records.json: the semantic record verify.py checks.

## Not claimed

- The body of any caller (sites and FDE ranges only).
- BlockBuilder::AddWithLastKey at 0x612a500 (sibling of Add,
  recorded only as the location of one annex Add call site).
- The local helpers the pinned bodies call: the vector
  default-append helper at 0x6129d90, the vector realloc-insert
  helper at 0x612a020, and the PLT stubs.
- EncodeVarint32 at 0x61bd410 (vendor-census identified only;
  Add's header varints are inline in the pinned body).
- rocksdb::Hash behaviour at its other 25 call sites beyond the
  shared byte rule pinned here.
- Whether anything in this binary reads the annex bucket array
  back (DataBlockHashIndex::Lookup at 0x612ce50 calls the
  pinned Hash leaf, but its own body is not pinned).
- The BlockBuilder destructor and the remaining members
  adjacent to the pinned cluster.
- Any mapping from these builder semantics to a specific
  on-disk table file.
