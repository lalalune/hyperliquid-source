# Input-only qualification transport

This is an independently designed transport for later source qualification,
not the node wire format or native result layout. No executable client exists
at this pre-code stage. All multibyte transport integers are unsigned little
endian. Every frame must end exactly at its declared end. IDs are opaque
`C000000`-style sequential labels; fixture names, family labels, expected results
and charge traces are excluded from the client input.

Each input line is `ID<TAB>lowercase_hex_frame<LF>`. The frame starts with ASCII
`G94R`, then one operation byte:

| Operation | Remaining fields before wire bytes |
| --- | --- |
| 0, supplied Reader | enabled u8 (only 0/1), limit u64, charged u64, cursor u64, wire length u32 |
| 1, selected EDX=0 caller | limit u64, wire length u32 |

Exactly wire-length uninterpreted bytes follow. For operation 0, cursor must
be at most wire length; the entire supplied span is retained so a nonzero
cursor is explicit. Operation 1 creates enabled=true, charged=0, cursor=0.
The transport is bounded by u32 input/output counts and available host memory.
This is a qualification envelope, not a native u32-length constraint.

The client must emit exactly one `ID<TAB>lowercase_hex_output<LF>` per admitted
line, in the same order. It receives only the input stream and normal runtime
configuration. It must not read `expected.tsv.gz`, `cases.jsonl.gz`, oracle
code, labels, target bytes or native exports. The independent parent compares
the complete unmodified output bytes against the pre-code frozen expectation.
Changing, omitting, duplicating or reordering lines must fail comparison.

For operation 0, the output is final absolute cursor u64, final remaining u64,
final charged u64, then one logical value. For operation 1, it is one logical
value, then consumed-option byte: 0 and no further data on error; 1 followed by
consumed u64 on success. An error's unavailable consumed word is not invented.

Every logical value starts with its one-byte native logical discriminator:

| Tag | Active transported fields, in order |
| --- | --- |
| 0 | V length u32, V bytes, Q u64, H32, map |
| 1 | V length u32, V bytes, Q u64, H32, first map, second map |
| 2 | V length u32, V bytes, Q u64, exactly three records |
| 3 | wire-order a u64, b u64, c u64 |
| 4..7 | no fields |
| 8 | active error |

A map is distinct-entry count u32, then that many entries in increasing
unsigned lexicographic key order. Each entry is key20, eight decoded u64 limbs
in wire order, and the unrestricted final byte. Its raw 72-byte native slot
padding is absent. A record is first scalar u64, second scalar u64, then exactly
2048 bytes, despite the native stored record putting its scalars after the bytes.

An active error starts with its one-byte kind. Kind 0 adds needed u64. Kinds 1
and 2 add nothing. Kind 3 adds expected u8 and found u8. Kind 5 adds ASCII-name
length u8, that many name bytes, inclusive lower bound u32, upper bound u32,
and found u32. No other kind is in the admitted ordinary-return relation.

Malformed transport, unsupported operation, invalid boolean/cursor, arithmetic
failure while sizing a transport frame, unavailable host allocation, or an
unrepresentable complete output count are source/transport policies. They must
be reported distinctly from native kinds 0/1/2/3/5. The frozen corpus consists
only of representable conditional-native cases. Later malformed-input controls
must not be reclassified as target-derived outcomes.

`corpus.py` constructs finite inputs; `oracle.py` derives mathematical grammar
and state outcomes before any later production source. `fixtures/cases.jsonl.gz`
is independent-parent metadata only. Its semantic names and full-result hashes
are never passed to the implementation. Corpus sampling does not establish a
universal proof; CONTRACT.md, PROOF.md and TREE-PROOF.md carry that obligation.
