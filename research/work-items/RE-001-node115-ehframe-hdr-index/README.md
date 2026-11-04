# RE-001-node115-ehframe-hdr-index: does the node #115 .eh_frame_hdr index exactly cover the .eh_frame FDE set?

- Component ID: RE-001 (#115 function map, P0) - the row whose acceptance requires accounting for duplicate and missing functions when FDE ranges are decoded.
- Target release and full SHA-256: node115, Linux x86-64 `hl-node`, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No reference source and no retired-release record is used as an oracle; every value below is derived from the pinned target bytes.
- Claim status: observation for every address, count and byte string listed here. The interpretation in "Results and limitations" is labelled as an inference.
- Scope included: geometry of `.eh_frame_hdr` and `.eh_frame`; the four header encoding bytes; the resolved eh_frame pointer, the FDE count and the binary-table address; the exact bytes of the first eight table entries; the comparison of those entries against the FDE starts and pc_ranges parsed from `.eh_frame`.
- Scope excluded: executing or emulating the target, runtime behaviour, a complete xref or function census, `.text` function-body or component-byte claims, #94 correspondence and any progress gate. No reconstruction credit is requested.

Bounded question: does the node #115 `.eh_frame_hdr` binary-search index exactly cover the `.eh_frame` FDE set (no duplicate starts, no omitted FDE starts, no index-only starts), and does a function end come from the FDE pc_range instead of the next index start?

## Reproduce

Static, read-only analysis of the pinned capture. `tools/foundation_ehframe_hdr_index.py` reads `artifacts/node/115/hl-node` in place (never copied, never executed) using only the Python 3.10 standard library (`struct`, `hashlib`, `json`). No network access and no external tool invocation.

```
python3 -B tools/foundation_ehframe_hdr_index.py --derive-json   # print every derived value
python3 -B tools/foundation_ehframe_hdr_index.py                 # compare against this packet
python3 -B -m unittest discover -s tests -p test_foundation_ehframe_hdr_index.py -v
```

The focused reproduction is the scratch verifier
`python3 test-results/slop-workbench/packet-caeeb8cbed5a.py`, which prints the derived
record and then asserts each packet file. Until `evidence.json`, `header.txt` and
`index.txt` exist it fails with an assertion that the packet directory or a packet file
is missing; that is expected progress, not a passing result. The committed test is not
yet written and is not claimed to have run.

Input identity is checked before parsing: the whole-file SHA-256 must equal the pinned
digest, otherwise the checker aborts. Addresses are ELF virtual addresses; for these two
sections the file offset equals the VA.

## Evidence

Section geometry of the pinned image:

| Section | VA | File offset | Size |
| --- | --- | --- | ---: |
| `.eh_frame_hdr` | `0xb9ea40` | `0xb9ea40` | 1,082,516 |
| `.eh_frame` | `0xca6ed8` | `0xca6ed8` | 7,803,772 |

`.eh_frame_hdr` header tuple:

| Field | Value |
| --- | --- |
| version | 1 |
| eh_frame_ptr_enc | `0x1b` (DW_EH_PE_pcrel \| sdata4) |
| fde_count_enc | `0x03` (udata4) |
| table_enc | `0x3b` (DW_EH_PE_datarel \| sdata4) |
| eh_frame_ptr | `0xca6ed8` |
| eh_frame_ptr_matches_section | true |
| fde_count | 135313 |
| table_va | `0xb9ea4c` |
| header_hex (first 32 bytes) | `011b033b9484100091100200c0a88700b0841000b0a98700e4eb4900e0ab8700` |
| header_sha256 | `e7995206b0e3b974a5eb46d1a2050e9949efcc5b8f0936684ba8660bf2711088` |

`.eh_frame` record census:

| Field | Value |
| --- | --- |
| fde_records | 135313 |
| nonzero_start_records | 135313 |

Index summary:

| Field | Value |
| --- | --- |
| entries | 135313 |
| first_start | `0x1419300` |
| last_start | `0x63f09f0` |
| monotonic_strict | true |
| duplicate_starts | 0 |
| missing_fde_starts | 0 |
| index_only_starts | 0 |

First eight index entries (slice), each as start then FDE record address:

| # | start | FDE |
| ---: | --- | --- |
| 1 | `0x1419300` | `0xca6ef0` |
| 2 | `0x14193f0` | `0x103d624` |
| 3 | `0x1419620` | `0x103d660` |
| 4 | `0x14196d0` | `0x103d688` |
| 5 | `0x1419900` | `0x103d6c4` |
| 6 | `0x14199b0` | `0x103d6ec` |
| 7 | `0x1419a60` | `0x103d714` |
| 8 | `0x1419c90` | `0x103d750` |

| Field | Value |
| --- | --- |
| slice_hex | `c0a88700b0841000b0a98700e4eb4900e0ab870020ec490090ac870048ec4900c0ae870084ec490070af8700acec490020b08700d4ec490050b2870010ed4900` |
| slice_sha256 | `0d8358dafb75a656677a5d709735efad3c290a71cf62849736829531be88f741` |

Extent comparison for the same slice:

| Field | Value |
| --- | --- |
| records_checked | 8 |
| positive_ranges | 8 |
| start_mismatches | 0 |
| end_differs_from_next_index_start | 7 |

## Implementation and comparison

No Rust implementation is part of this packet; it contributes no first-party component
bytes and requests no progress gate. The checker re-derives every recorded value from
the pinned bytes and compares it with `evidence.json`, then byte-compares `header.txt`
and `index.txt`. A corruption control alters the derived version byte and requires the
same comparison to reject it.

## Results and limitations

Observation: 135,313 FDE records were parsed from `.eh_frame`, all with a non-zero
start; the header index holds 135,313 entries that are strictly monotonic, with zero
duplicate starts, zero FDE starts missing from the index and zero index-only starts.
Observation: in the checked slice, 8 of 8 recorded starts equal the corresponding FDE
start and 8 of 8 carry a positive pc_range; in 7 of 7 adjacent pairs, FDE start plus
size differs from the next index start.
Inference: because the index start list equals the FDE start list and the FDE extent
endpoints differ from neighbouring index entries, a function end inside this band must
be read from the FDE pc_range, not from the next unwind-index start.
Limits: only the first eight entries are byte-compared and extent-compared; the whole-set
start comparison is a comparison of decoded values, not a per-function body analysis. No
execution, no behaviour, no complete function map and no gate. Whether every FDE
corresponds to a distinct first-party node function is not established here.

Next question: select one complete FDE whose body is first-party node code rather than a
dependency leaf, and bind its extent, body hash and direct callers to the reconstruction.
