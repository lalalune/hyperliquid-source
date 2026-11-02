# Tagged copy with arbitrary admitted overlap

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
complete linked ELF VA `[0x22155a0,0x22155c0)`, 32 bytes and eight
instructions. The claim is final ordinary memory and full numeric RAX,
not a source type, tag meaning or System V ABI replacement.

## Exact local closure

The complete unique FDE and its raw CIE are retained. GNU, LLVM and
Capstone agree on every body byte and instruction boundary. There are
no branches, calls, RIP-relative data accesses or helper dependencies.
The next FDE starts at `0x22155c0` and ends at `0x2215859`, so there is
no padding after the leaf. No direct E8 candidate targets this entry
in the full `.text` scan; no RELA addend names it and no relocation
overlaps the code. These scans do not enumerate indirect/computed
callers or establish the provenance of the source function.

The first MOV copies incoming RDI (destination O) into RAX. No other
instruction writes RAX, so every normal return retains the entire
numeric O, including zero and high bits. The two MOVUPS loads snapshot
initial source bytes `[S,S+16)` and `[S+16,S+32)` into XMM0 and XMM1.
They complete before any output store. The stores then write the second
snapshot at O+24 and the first snapshot at O+8. MOVABS materializes
`0x8000000000000014` and the final qword store writes it at O.

## All-byte final relation

Let M be the initial ordinary-memory byte mapping, with all required
accesses valid. Let T be little-endian bytes `14 00 00 00 00 00 00 80`.
On the admitted nonwrapping ranges the complete final relation is:

```
M'(x) = T[x-O]           if O <= x < O+8
        M[S+x-O-8]      if O+8 <= x < O+40
        M[x]            otherwise
RAX = O
```

Both source chunks are initial-memory snapshots. Therefore the relation
holds for every relative source/destination displacement, including
identical addresses, overlap with the tag, forward overlap, backward
overlap and disjoint ranges. A forward or backward byte loop alone
does not generally implement it. Storing the tag before capturing the
payload also changes the result when it overlaps source bytes.

The three output intervals are disjoint. Once both input snapshots are
captured, combining the two 16-byte payload stores into one 32-byte
slice copy preserves this final relation. It does not claim the same
store instructions, intermediate observations or fault ordering. The
new Rust first copies the complete 32-byte source to a local array,
then writes that array at O+8 and the exact tag at O. Thus each final
byte satisfies the formula, independently of the contents of all
other image bytes. No guessed alignment or tag interpretation is used.

## Checked-image domain

The new API receives one mutable byte image with numeric base B, a
source address S and a destination address O. Image index j represents
address B+j. The entire image must be nonwrapping; an image whose last
byte is u64::MAX is valid. The selected source 32-byte and destination 40-byte
ranges must both be completely within it. Address subtraction and
usize conversion are checked without truncation; checked length
addition proves the slice ranges are valid. The resulting fields and
payload positions cannot wrap on an admitted range.

`ImageRange`, `Input` and `Output` are new safe refusals in that priority
order. All checks precede every write; any refusal leaves every backing
byte unchanged. The captured code can fault after earlier accesses or
stores, so these refusals are not represented as original outcomes.
A contiguous nonwrapping image is an explicit domain restriction, not
a claim that all possible target memory layouts have this shape.

Correspondence requires stable ordinary readable/writable memory for
the actual target accesses and valid code/control storage. Code or
return-stack aliases, MMIO, concurrent mutation, page faults, intermediate
external observations, XMM/RCX state, flags and timing are excluded.
Numeric high-address tests do not assert host mapability. No returned
number is dereferenced as a host pointer. The proof covers every
admitted input byte pattern and all numeric S/O/B values satisfying
these bounds.

## Independent qualification

Before either Rust file existed, the static record, oracle hash and
input/output streams were frozen. The oracle constructs every final
byte directly from the immutable initial image and the piecewise
formula; it does not execute stores, target instructions or Rust.
The native driver receives input bytes only and returns a status, raw
RAX and all 128 backing bytes, including outside an admitted prefix.

The 8,003 fixed cases comprise 6,136 normal results and 1,867 new safe
refusals (7 ImageRange, 1,415 Input, 445 Output). They include 5,465
admitted overlaps and 368 identical-address cases. Every overlapping
displacement from -39 through 31 is exercised at all eight input
alignment phases with four byte patterns. Every one of the 256 payload
bits is separately set at eight representative overlap displacements.
Exact-end, one-byte-short, high-base and partial-image cases plus seeded
additional values exercise the admission and outside-range behavior.

All 32,012 native observations agree in two builds each at opt0/opt3,
with identical repeated libraries, clients and output streams. Three
unit tests/profile, malformed driver framing and two comparator
controls pass. All 13 compiled mutants differ: early tag writes change
3,197 admitted outputs; delayed second loads change 2,046; forward and
backward byte loops change 2,430 and 1,709. A strict endpoint control
causes 150 false refusals and zero admitted-value mismatches, reported
separately from value controls. All 120 command streams, exact source
and tool hashes and first counterexamples are retained losslessly.

Fifteen static controls corrupt body operands, tag bytes, CIE/FDE and
the next-FDE start. Downstream control validation excludes the global
target digest from record comparison, so a failed identity check does
not stand in for structural detection. Host-native qualification uses
the pinned macOS aarch64 rustc 1.94.1 toolchain. No captured code or
instruction emulator runs, and no target compiled-byte identity,
whole-node equivalence or progress-gate completion is claimed.
