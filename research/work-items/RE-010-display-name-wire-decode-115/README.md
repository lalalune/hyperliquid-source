# RE-010: bind SetDisplayName wire decoding to its #115 payload arm

This packet follows the exact type string `setDisplayName` through the #115
action-name matcher to `Action` variant index 19, then through the selected
`Action` decoder arm to its `SetDisplayNameAction` field descriptor, payload
decoder and internal discriminant `0x99`. Existing
`RE-010-display-name-path-115` evidence maps discriminant `0x99` to the direct
display-name handler. This packet closes the input-name-to-decoder gap left by
that work; the connection from the decoder's returned object to the later
execution router remains a static same-discriminant linkage, not a captured
runtime trace.

- Component: `action-dispatch` (RE-010).
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base commit: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.
- Claim status: byte, table, relocation and FDE observations; Rust/serde role
  names and the cross-packet decoder-to-execution linkage are inferences.
- Scope: one 14-byte action type name, its index-19 decoder-table entry, the
  selected payload helper call and field-name descriptor. Excludes the full
  `Action` decoder CFG, every malformed-input path inside the payload helper,
  runtime execution, authorization/state-write revalidation and a Rust
  implementation.

## Reproduce

From the repository root on Python 3.10 or newer:

```sh
python3 tools/re010_display_name_wire_decode_115.py
python3 -m unittest tests.test_re010_display_name_wire_decode_115
(cd research/work-items/RE-010-display-name-wire-decode-115 && shasum -a 256 -c MANIFEST.sha256)
```

The generator checks the full artifact digest, selected FDE boundaries,
relative branch-table entry, name comparison, field-name relocation and helper
call before writing evidence. It uses only the Python standard library and
`tools/elf_index.py` / `tools/fde_extents.py`. It does not invoke or execute the
captured binary. All addresses are linked ELF virtual addresses; windows and
function records retain exact raw bytes or SHA-256 values.

## Evidence

### Name to variant index

The caller `0x21dfc90` has borrowed and owned-name arms that call
`0x2ba0a70` at `0x21dfcc7` and `0x21dfd1e`; this edge is recorded in the
existing `RE-010-gov-vote-path-115` packet. In the matcher FDE
`0x2ba0a70..0x2ba1aef`, the length-14 switch arm starts at `0x2ba0d30`. Its
two overlapping 8-byte comparisons at `0x2ba0d54` and `0x2ba0d61` reconstruct
the exact byte string `setDisplayName`. The equal branch reaches `0x2ba19af`,
which stores `0x13` (decimal 19) at output offset `+1` and joins the matcher's
common return at `0x2ba1ae5`. The length-14 table entry at `0x608568`
selects compare arm `0x2ba0d30`.

### Variant index to payload decoder

The outer `Action` decoder is FDE `0x2b817d0..0x2b84365`. Its index switch
uses table base `0x607028`. Slot `0x607074` (index 19) contains signed
relative displacement `0x0257c653`, which resolves to arm `0x2b8367b` inside
that FDE. The arm loads the literal `SetDisplayNameAction` at `0x5edfbf`,
passes field descriptor `0x642f3f0`, and directly calls payload helper
`0x20647f0` at `0x2b8369c`.

The descriptor begins with an `R_X86_64_RELATIVE` relocation from
`0x642f3f0` to `0x5ed54a`; the adjacent length is 11 bytes, and those bytes
spell `displayName`. The selected action arm's normal path sets `r14d` to
`0x99` at `0x2b836bc`. Its shared return path stores that qword at output
offset 0, allocates 0xf0 bytes, copies the object, then returns its pointer in
`rdx`. The existing display-name router packet shows the router loading a
qword at input offset 0 before selecting tag `0x99`. This establishes a
matching static object layout across the two packets; it does not prove that
this exact returned pointer reaches that exact router call at runtime.

The payload helper is the whole FDE `0x20647f0..0x2064ffc`. Its entry
distinguishes first-byte values `0x14` and `0x15`; this packet records that
observation but does not assign source-level map/sequence labels or claim all
helper branches are reconstructed.

The sister packet `RE-010-display-name-path-115` independently maps action
index 19 / tag `0x99` to the direct handler and records its guards, mutation
and result branches. The `govVote` packet covers index 50 in the same outer
decoder with a different helper (`0x20aedb0`); it does not cover this
SetDisplayName arm. The serializer mapping in #7089 and the method-arm map in
#7082 cover different directions and are not reused as proof of the incoming
wire decode.

## Implementation and comparison

No Rust implementation or execution comparison is claimed. The Python
generator independently extracts and checks the selected addresses and
relationships against the pinned ELF bytes. The machine-readable output has
no estimated whole-component denominator. The focused tests check regeneration,
captured digest rejection and output stability; repository-level results are
reported in the pull request after they finish.

## Results and limitations

The generator reports one wire-name/index edge, one index/table/arm edge, one
payload-helper call, one relocated field name and the internal tag. This
supports the observed path from the external `type` spelling to an internal
`0x99` payload variant. Matching tags and table positions across the decoder
and execution packets support the inferred linkage, but there is no captured
runtime trace joining the return object to the router call. The payload helper
contains additional map/array, field validation, allocation and error paths
not reconstructed here; no component or issue gate is requested.

Next question: can a static caller/dataflow trace identify where the returned
`Action` object is handed to the `0x99` execution router without inferring the
connection solely from the shared discriminant?
