# Entry-snapshot byte reversal within four-byte lanes

## Exact bound body

This proof concerns node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
complete ELF VA interval `[0x56544a0,0x56544f0)`: 80 bytes and 22
instructions. Full-target authentication precedes structural parsing.
The complete 121,299-FDE inventory has one exact overlapping FDE for this
body; its full record and shared CIE are bound separately. GNU and LLVM
agree on every byte and instruction boundary, including the final two-byte
`repz ret` at `0x56544ee`.

The next FDE begins exactly at `0x56544f0` and ends at `0x5654509`; its
record is bound only to establish this boundary and **zero padding**.
That adjacent byte-copy function is not reconstructed or included as a
second member. The preceding function's padding is also outside scope.
The body has no calls or branches outside its bound range, no internal
conditional branch, and no RIP-relative data/global requirement. Complete
`.text` E8/E9 byte-pattern scans find zero incoming candidates. All 80,300
RELA records contain no addend naming this entry and no destination
writing over its body. Indirect and other pointer references are not a
complete xref census, so absence of runtime callers is not asserted.

## All reads precede the first write

Let S and D be entry RSI and RDI. The four little-endian qword reads are:

| Instruction | Read | Destination |
| --- | --- | --- |
| `0x56544a4` | S+0 through S+7 | R8 |
| `0x56544a7` | S+8 through S+15 | R9 |
| `0x56544ab` | S+16 through S+23 | R10 |
| `0x56544b2` | S+24 through S+31 | R11 |

The intervening BSWAP changes only R8. No data is written before all four
loads complete. The first store is at `0x56544b9`. Thus the register-held
words represent one complete **entry snapshot** of all 32 source bytes,
even if source and destination partially or completely overlap.

Four BSWAP operations reverse each register's eight bytes. The low dword
of each reversed register is stored at D+4, D+12, D+20 and D+28, in that
order. Each register is shifted right by 32 and its remaining low dword
is stored at D+0, D+8, D+16 and D+24. The shifts are interleaved with those
stores, but cause no further data read. These eight destination ranges
are disjoint within the admitted nonwrapping 32-byte destination.

## Byte equation and aliases

Write the entry source bytes as `s[0]..s[31]`. For qword k, little-endian
loading gives `w = sum(s[8k+j] * 256^j, j=0..7)`. BSWAP produces the word
whose little-endian bytes are `s[8k+7]..s[8k]`. Its low dword store at
D+8k+4 therefore gives, for j=0..3,

`out[8k+4+j] = s[8k+7-j]`.

After shifting that reversed word right by 32, the low dword store at
D+8k gives

`out[8k+j] = s[8k+3-j]`.

Equivalently, for every output byte index i in 0..31,

`out[i] = entry_source[i XOR 3]`.

This reverses the bytes **within** each four-byte lane, leaving lane
positions fixed. It neither swaps two unchanged halves of a qword nor
reverses an entire qword or entire buffer. For input `01 02 03 04 05 06
07 08`, output is `04 03 02 01 08 07 06 05`. The historical scout's half-swap
label was already corrected by the predecessor packet; this contribution
uses the corrected byte relation and does not rely on that packet's
historically mentioned instruction-semantics emulation.

Since every source read preceded every store and destination subranges
do not overlap one another, the final state is this single entry-snapshot
patch for **all** source/destination overlaps and unaligned displacements.
Bytes outside D..D+31 are unchanged. Reordering stores after the snapshot
would not change this ordinary-memory final-state projection. Replacing
the snapshot with live per-lane reads can change later inputs under aliases
and is not equivalent.

No instruction writes RAX. Therefore its complete entry bit pattern is
preserved at the ordinary return. R8..R11 and flags are modified; they are
not projected by the API. No source-level return type or purpose is inferred.

## Safe image API and exact admission

`reverse_lanes(image, base, source, destination, entry_rax)` represents one
nonwrapping abstract u64-address interval `[base,base+len(image))`. The
exclusive endpoint may equal `2^64`. Both complete 32-byte source and
destination ranges must fit in that interval; they do not wrap through
address zero. Addresses and the incoming RAX value are numerical inputs,
not native pointers. Any partial or exact overlap between these two data
ranges is admitted, and no alignment is required.

The function validates the whole image and both ranges before writing.
It then copies the entire 32-byte source into a stack array, reads each
four-byte array chunk as a little-endian u32, and writes its big-endian
bytes to the same lane position at the destination. For bytes a,b,c,d,
that conversion writes d,c,b,a, precisely the equation above. All eight
source chunks are taken from the immutable entry snapshot. Range admission
bounds every slice and conversion, so the internal array conversions
cannot fail. The result is the supplied full `entry_rax`, preserving the
observed identity relation for every u64 bit pattern.

`Err(Unavailable)` is a new safe refusal for an unavailable/nonconforming
image/range. It always leaves the entire image unchanged. This is not
native fault recovery: native stores could have partial effects on a
faulting destination, which is outside the correspondence claim. The
stronger nonwrapping contiguous-range domain is explicit; arbitrary wrapped
native-pointer layouts are not reconstructed.

Original correspondence requires initialized, stable ordinary source data,
readable source/writable destination ranges, and valid unchanged code and
ordinary return control disjoint from writable data. Numeric admitted
images are not promises that corresponding OS process mappings exist.
We exclude MMIO/volatile effects, concurrent/asynchronous changes, faults,
code modification, control-stack/data writes, access traces, flags,
R8..R11 results and original pointer ABI. Rust's function return is the
projected RAX value, not an assertion about the original source signature.

## Independent expectations and qualification boundary

Before Rust existed, `oracle.py` froze its own source and 8,553 exact
input/output rows. It computes an entry-image byte-index patch using
`i XOR 3`; it contains no word-byte-swap/endian conversion, opcode dispatch,
register/flag interpreter or captured execution. The later Rust uses a
complete source snapshot and u32 endian conversions. Their equivalence
comes from the byte equation above, not only their finite agreement.

The corpus covers all overlapping byte displacements in both directions,
all input bit bases under seven alias placements, exact/short boundaries,
high bases and complete-range refusals, deterministic random images and
full-width entry RAX values. Coverage separates disjoint, partially
overlapping and identical ranges from image/range refusal. The input-only
client has no expected outputs; it receives only input TSV and emits full
status/RAX plus lossless changes over every image byte. There are no masks.

Native opt0 and opt3 builds are each repeated, requiring identical rlib,
client and output hashes within a level. Compiled mutants must terminate
normally and differ observably; they include live-source processing,
historical half-swap, full-word/buffer reversal, out-of-destination writes,
premature writes on a refused path and wrong RAX preservation. A reversed
store iteration after a complete snapshot is mathematically equivalent on
this domain and is not counted as a killed mutation.

Static controls operate below the full-target hash check for structural
body/FDE/CIE/census corruption tests. Comparator/archive corruption controls
and exact lossless raw streams accompany the observed results. Native
execution is limited to newly authored Rust. No captured executable or
instruction emulator, native-target differential, original compiled-byte
identity, whole-node equivalence or progress gate is claimed.
