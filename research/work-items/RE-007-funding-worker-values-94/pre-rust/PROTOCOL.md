# Input-only corpus framing

All integers are little endian with the signedness stated. Each concatenated
frame is `id:u64 | payload_length:u32 | payload`; ID is opaque and carries no
expected value. Truncated/extra payload bytes, duplicate map/set keys, duplicate
IDs or unreasonable allocation counts are driver refusals, not native errors.
The driver must bound every count by remaining frame bytes before allocation.
Input and expected files are separate deterministic gzip streams. Empty stream
is allowed; actual corpus count is frozen in fixtures/corpus.json.

Input payload:

1. address20, bypass:u8, raw_time12, user_balance:i64.
2. membership_count:u32 followed by that many address20 entries.
3. metadata_count:u32 followed by that many i64 selected row words.
4. rate_count:u32 followed by pairs `(asset:u64, raw_rate:u64)`.
5. position_count:u32 followed by 52-byte entries
   `(asset:u64, tag:u32, local:i64, size:i64, accumulator0:i64,
     accumulator1:i64, accumulator2:i64)`.

Set/map entries are serialized in ascending order. The intended driver accepts
only strictly increasing entries, making the collection meaning unambiguous.

Output payload begins status:u8. Status2 is a safe API refusal, followed only
by asset:u64 and reason:u8 (0 metadata index, 1 negative metadata word,
2 signed product overflow, 3 finite amount MIN). This frame claims no native
failure state. Status0 or1 is followed by returned user balance:i64,
position_count:u32 and the same 52-byte position encoding in key order.
Status0 then ends (excluded membership and unchanged modeled values).

Status1 continues with row_count:u32 and fully active 72-byte rows:
`asset:u64, payment:i64, original_size:i64, raw_rate:u64, product:i64,
address20, raw_time12`. Then `sum:i64, has_max:u8`; when has_max1 append
`selected_asset:u64, unsigned_magnitude:u64, selected_address20`.
Finally append request_count:u32 and 9-byte requests `(asset:u64, field:u8)`.
Field0 is selected balance subtraction, fields1..3 are accumulator0..2 addition,
field4 is summary saturation. These record conceptual call requests, not
native logging success or extra native ABI arguments. No capacity, pointer,
padding, inactive union word or NaN multiplication payload is serialized.
