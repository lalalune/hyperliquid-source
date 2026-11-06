# RE-012: node #115 compressor dictionary geometry and candidate probe

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; transport / RE-012.
MIT new research; no inferred reference implementation or public codec source
was copied. The complete compressor algorithm remains open.

## Question and new result

The sender-selection result distinguishes 8192/16384-byte scratch allocations,
but does not establish their element widths or what a candidate lookup does.
This packet derives those properties from both actual loop bodies rather than
naming a table type from allocation size alone. Observations are ELF VAs,
without rebasing or byte normalization.

| Selected entry | Full FDE | Input hash operand | Wrapping product and shift | Bucket access |
| --- | --- | --- | --- | --- |
| small | 0x477e950..0x477f036 | little-endian DWORD | low32(word * 0x9e3779b1) >> 20 | WORD, index * 2 |
| large | 0x477f040..0x477f746 | little-endian QWORD | low64(word * 0xcf1bbcdcbb000000) >> 52 | DWORD, index * 4 |

The large entry loads eight bytes but its hash depends only on the low
40 bits (five bytes): its multiplier has 24 trailing zero bits, so changing
the top 24 input bits changes the product only by a multiple of 2^64.
Those changes vanish before the right shift. This follows algebraically from
the captured constant, not from a sampled collision claim.

Both shifts leave exactly 12 bits, hence 4096 index values. The byte spans
4096*2=8192 and 4096*4=16384 agree with the sender's distinct allocations.
This establishes bucket geometry, not the allocator's initialization contract.
At `0x477ea0c..0x477ea1d` / `0x477f0fc..0x477f119`, a selected startup arm
writes zero to **one hashed bucket**, then sets the probe position to one.
That arm is entered only when the OR of the saved origin/auxiliary word and
initial position is zero. It is not a whole-table clearing loop. Valid initial
contents and precise source types of those raw words remain unknown.

## Ordered probe effects and rejection

The selected small probe at `0x477eab4` loads four source bytes; the large
probe at `0x477f1a4` loads eight. Both compute the index above, load the
old table cell into ECX, and **store the current absolute position into that
cell before checking whether the old candidate is usable**. The small store
truncates to BX/u16; the large store truncates to EBX/u32. Thus even a rejected
candidate updates its bucket. Any reconstruction that updates only after a
successful match would change the next lookup's state.

Small `0x477eacb..0x477eafb` and large `0x477f1c5..0x477f1f9` then:

1. Subtract candidate from current absolute position; borrow takes an opaque
   failure-helper path, not an ordinary mismatch continuation.
2. Subtract the saved origin from the candidate; borrow resumes probing.
3. Reject distance >= 65536 by resuming probing (65535 is not rejected by
   this local comparison). No nonzero-distance claim follows from this check.
4. Check candidate-relative +4 against source end; exceeding it takes a
   failure-helper path. Compare four bytes at the candidate with the current
   input's low DWORD; inequality resumes probing.

The large entry's eight-byte hash load therefore does **not** make its initial
match comparison eight bytes wide. Later forward/backward extension, match
length production, output offsets, literals and error objects are outside this
bounded probe claim.

Both loops initialize the skip counter to 32, derive the next position as
old_position + (counter >> 5), and increment counter on each failed candidate.
Checked additions and counter overflow have separate failure edges. The
retained complete bodies preserve those edges; this packet does not simulate
them or assert a public streaming-dictionary API.

## Evidence and limits

Two complete FDE contexts: 3564 bytes / 809 instructions, already exported
as context by sender-selection research and not new byte-coverage credit.
The new semantic anchors cover hash width/constants, stores-before-guards,
rejection ordering, single-bucket startup and skip increment. records.json
binds the full body hashes, FDE/CIE records, calls, branches and actual
relocation writers. Complete GNU/LLVM partitions agree with Capstone; GNU
readelf independently checks both extents. The exact 4096-bucket range follows
from instruction widths and shifts, not a sampled distribution claim.

Reproduce from repository root, with Python 3.14.5 / Capstone 5.0.7,
GNU binutils 2.45 and LLVM 23.1.4:

```
python3 -B research/work-items/RE-012-lz4-dictionary-probe-115/verify.py
make doctor verify catalogue-check reproduce
```

The verifier freshly authenticates the target, regenerates native exports and
records, rejects two identity corruptions, and changes one actual byte per
anchor while bypassing only the full-file hash guard for that narrow negative
control. It does not execute/emulate the capture or supply a Rust dictionary.
The preceding 583-file test qualification applies to unchanged base/test code
(zero nonzero exits, 25 authorization/environment skips); it is not reported
as a new full suite run. New focused checks are recorded in validation.json.
All full-scope gates and compiled-byte totals stay unchanged. Next: establish
scratch initialization, origin constraints and the subsequent match-emission
path before treating either entry as a recovered compressor implementation.
