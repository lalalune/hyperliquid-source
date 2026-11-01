# Input-only rate value protocol

Each ASCII input record is one TAB-separated, LF-terminated line:

`ID interest multiplier clamp samples [sample_bits ...]`

ID is exactly16 lowercase hexadecimal characters and is opaque. Interest and multiplier are either `-` (missing) or exactly16 lowercase hex characters. Clamp and each sample are exactly16 lowercase hex characters. The samples field is either `-` (missing, no following words), or a canonical nonnegative decimal count (no leading zeros except `0`) followed by exactly that many sample words. A count of0 means a present-empty sequence. All bit words are raw u64 encodings; no decimal float parsing occurs.

The eventual client must reject malformed text, missing final LF, invalid or duplicate IDs, extra/missing fields, noncanonical counts and count/type overflow with nonzero exit and no partial successful output. Empty input produces empty output. Type/protocol rejection is newly chosen policy, not a native error claim. A declared huge count with fewer fields is rejected before allocating for that count. The safe borrowed-slice operation has the language's ordinary valid-slice length domain.

For each input emit exactly:

`ID optional_rate inserted_rate\n`

Separators are TAB. Optional rate is `-` only for absence, otherwise16 lowercase hex digits. Inserted rate is always16 lowercase hex digits: positive zero for absence, identical to the optional active bits otherwise. Present+0 and absence therefore remain distinct in the first field; present-0 and NaN bits remain exact in both fields. Ordered IDs, line count and all bytes must match; no NaN-class-only normalization, sorting or omitted rows is allowed.

The later Rust client can read only this input stream and link the real crate. It may not open expected files or semantic provenance, import the oracle, accept expected-output paths or use fixture IDs to choose results. Only the outer comparator reads expectations. Baseline/rebuild profiles and every compiled semantic mutant must emit their own complete streams. Comparator and malformed-input controls must exercise actual rejection behavior.
