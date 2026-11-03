# RE-001: node #115 LSDA header and call-site table for one FDE-bound function

- Component ID: `foundation` (RE-001, #115 function map / exception metadata).
- Target release and full SHA-256: node #115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no reference source is used as an oracle.
- Claim status: observation (static byte analysis of the pinned image).
- Scope included: the ELF section geometry for `.text`, `.eh_frame` and `.gcc_except_table`; the `.eh_frame` CIE/FDE census; the single CIE that owns the selected FDE; the FDE for `0x14193f0..0x1419618`; the `.gcc_except_table` LSDA header it references; the complete call-site table declared by that header; and four corruption controls.
- Scope excluded: any runtime/behaviour claim, landing-pad code semantics, the personality routine body, type-table entries, LSDA tables of other FDEs, and any reconstruction or progress gate.

## Question

Which LSDA header fields and call-site table does the pinned node #115 FDE for
`0x14193f0..0x1419618` reference, and do the corruption controls reject altered
inputs?

The FDE is selected deterministically by the checker: it walks `.eh_frame`, keeps
FDEs whose CIE declares an LSDA pointer encoding and whose LSDA target lands
inside `.gcc_except_table`, decodes each candidate LSDA, keeps those whose
declared call-site table length is between 12 and 127 bytes with at least two
call sites, and takes the lowest entry address. That selection yields
`0x14193f0..0x1419618`, and the recorded values below describe exactly that one
record.

## Reproduce

Platform: the repository's network-less validation workspace, reading the pinned
target in place. The checker never executes, copies or emulates the target.

```sh
python3 -B -m unittest discover -s tests -p test_foundation_lsda_call_site.py -v
python3 -B tools/foundation_lsda_call_site.py --target artifacts/node/115/hl-node \
    --packet research/work-items/RE-001-node115-lsda-call-site
```

The checker authenticates `artifacts/node/115/hl-node` by full SHA-256 and size
before parsing, then re-derives every value recorded here and compares it field
by field with `evidence.json`. The committed test exercises the same checker,
the target identity, the FDE extent, the call-site coverage, the corruption
controls, the packet comparison, and a CLI accept/reject pair.

## Evidence

Addresses are virtual addresses in the pinned image; file offsets are the
corresponding section-relative byte offsets.

| Section | VA | File offset | Size |
| --- | --- | --- | ---: |
| `.text` | `0x1419300` | `0x1418300` | 83,719,936 |
| `.eh_frame` | `0xca6ed8` | `0xca6ed8` | 7,803,772 |
| `.gcc_except_table` | `0x16c2c0` | `0x16c2c0` | 2,900,276 |

`.eh_frame` census over the pinned bytes: 3 CIEs, 135,313 FDEs, 52,682 FDEs
carrying an LSDA pointer, and 41,899 FDEs whose LSDA decodes into a bounded
call-site table under the selection rule above.

CIE (record offset `0x39672c`, raw bytes
`1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000`):
version 1, augmentation `zPLR`, code alignment 1, data alignment -8,
return-address register 16, FDE pointer encoding `0x1b` (pcrel sdata4),
LSDA pointer encoding `0x1b`, personality encoding 155 (indirect) with value
105,839,144.

FDE (record offset `0x39674c`, raw bytes
`3800000024000000c4bd3d0028020000048bec12ff410e10420e18410e20470ec00383048e03860203db010e20410e18420e10410e08410ec0030000`):
entry `0x14193f0`, end `0x1419618`, range 552 bytes, initial-location encoding
`0x1b`, augmentation data length 4.

LSDA (VA `0x16c2c0`, file offset `0x16c2c0`, encoding `0x1b`): header bytes
`ffff0115` give LPStart encoding 255 (omitted), TType encoding 255 (omitted),
call-site encoding 1 (uleb128), and declared call-site table length 21 at header
offset 3. The call-site table bytes are
`22098d04002bd0030000fb03108d04008b041d0000`, and its four records are:

| Index | Start offset | Byte length | Landing pad | Action |
| ---: | ---: | ---: | --- | ---: |
| 0 | 34 | 9 | `0x20d` | 0 |
| 1 | 43 | 464 | `0x0` | 0 |
| 2 | 507 | 16 | `0x20d` | 0 |
| 3 | 523 | 29 | `0x0` | 0 |

The four byte lengths sum to 518, which is less than the 552-byte FDE range;
the remainder is not covered by a call site.

Corruption controls, all computed in memory from the pinned bytes and all
rejected:

- `eh-frame-record-length-overflow`: an FDE record length that overruns `.eh_frame`.
- `lsda-pointer-outside-section`: an LSDA pointer past the end of `.gcc_except_table`.
- `call-site-table-truncated`: the LSDA buffer cut one byte before the declared table end.
- `declared-table-length-shortened`: the declared call-site length reduced by one.

## Results and limitations

Machine-readable metrics: 3 sections, 1 CIE, 1 FDE, 1 LSDA header, 4 call-site
records over a declared 21-byte table, and 4 of 4 corruption controls rejected.
The denominator for the call-site claim is the single FDE-bound LSDA record
recorded here; the census counts describe how many FDEs were examined, not how
many were validated in detail.

- This is static parsing of the pinned bytes only. No instruction in the target
  was executed, and no runtime landing-pad, unwinding or exception behaviour is
  claimed.
- The personality routine body and the type-table contents are outside this
  packet; the recorded personality value is a pointer, not a resolved symbol.
- The selected FDE is one function's exception metadata. It does not establish
  a complete function map, function names, or component ownership.
- No reconstruction, byte-equivalence or progress gate is claimed.

Next question: resolve the personality routine at 105,839,144 and the type-table
entries that the omitted TType encoding leaves unread for this window, so the
unwinding path for this FDE can be described from bytes rather than inference.
