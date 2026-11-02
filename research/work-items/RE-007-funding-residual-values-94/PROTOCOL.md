# Pre-code input-only protocol

No executable client exists at this pre-code stage. The future qualification
client accepts stdin only, one `Cdddddd<TAB>lowercase_hex` frame per line, and
must emit the identical opaque ID plus one lowercase hexadecimal result frame.
IDs are inert sequential labels; semantic names appear only in cases metadata.
The client receives no expected result, fixture path, case count, semantic name,
expected hash or outcome hint. A parent process compares every complete result
frame against independently frozen expected.tsv. No target evaluator is used.

All integers are little-endian fixed-width. Addresses are exactly20 raw bytes;
records exactly72 raw bytes. Counts below are u32 unless stated otherwise.
Reject truncated fields, unsupported versions/kinds/options, duplicate state
map/set keys, noncanonical IDs/hex, trailing bytes and extra command arguments.
Parse every frame before printing any result; malformed transport input is not
an operation-level safe rejection. The future client must preserve input order
and produce exactly one output line per valid frame, without timing fields.

## Input frame

Common prefix: version:u8=1, kind:u8.

Kind0: summary_count followed by that many summaries, then state. A summary is
address20, total:i64, selection:u8 (0/1), optionally asset:u64 and magnitude:u64
when selection=1, then record_count and that many raw72-byte records. Summary
keys may repeat so the safe API's duplicate rejection can be qualified. The
selected address is the summary key by typed construction. This encodes the
native tag0/1 and selected-address equality domain; it does not test native
arbitrary-tag rejection or native constructor behavior.

State is user_count then users; each user is address20, cross_balance:i64,
position_count:u64, map_entry_count then entries. Each position is asset:u64,
raw_mode:u32, leverage:u32, margin:i64, size:i64. Next come ARU count+addresses,
auxiliary count+(asset:u64,value:i64) entries, users-with-positions count+addresses.
Every state collection is uniquely keyed. The frame writer sorts state keys;
the client must admit unique entries independently. Summary order is unsorted
and is meaningful input to the source admission, although native-corresponding
output uses address ordering. Unselected position sizeMIN is permitted.

Kind1: summary_count:u64, total_input_record_count:u64. This invokes the actual
public checked-count helper that the operation itself uses. It accepts exactly
when `104*n <= i64::MAX`, `80*n <= i64::MAX`, and `72*m <= i64::MAX`. These
are native record/allocation provenance bounds. They are not Rust layout or
capacity promises; checked sum of all input row lengths precedes flattening.
The additional all-input row bound is a conservative safe policy. Huge counts
are admitted mathematically without pretending to allocate those vectors.

## Output frame

Common prefix: version:u8=1, kind:u8.

Kind0: status:u8, then success fields only for status0, then the complete state
in the same canonical encoding. Status0=ok,1=duplicate_summary,2=span,
3=missing_user,4=missing_position,5=size_magnitude. Every safe rejection keeps
initial state. No records/total/winner are emitted on rejection; this is the
safe value API contract, not a statement about native partial failure writes.

Success fields: total:i64, winner:u8 (0/1), optionally address20+asset:u64+
magnitude:u64, followed by flattened record_count and all output records.
An inactive zero-total path still reports a winner if the summary relation has
one, but does not access or alter selected state. Result total/winner are explicit
safe observations of intermediate values, not an asserted native output ABI.

Kind1: accepted:u8 (0/1).

## Corpus trust boundary

`corpus.py` uses flat sorted records and arbitrary-precision arithmetic. Winner
selection is a stable sort by negative magnitude and address; auxiliary output
uses `max(old,MIN+abs(size))`, independently of the native ordered two-store form.
It does not import a source implementation, native evaluator, or pending PR.
The generated cases metadata distinguishes native_corresponding from safe_policy.
Only the former have native conditional correspondence under CONTRACT.md.
A finite corpus supplements the manual all-domain argument; it does not prove
universal native correctness. Separate tree-token certificates test the complete
split-gap algebra, not native heap manipulation or machine instructions.
