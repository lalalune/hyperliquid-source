# Existing-provider correspondence and input-only bridge

This phase adds qualification code only. The merged MIT provider at
`src/node94-action-signable/src/keccak.rs`, SHA256
`2be9be79ce1324545fc2f7a45b572c54d9a587faf22412042458cb3f89bb1ab8`,
and its complete 11-file crate tree remain unchanged. The pre-code freeze
`12263950e60ce1b78ec3bb6d44c619ada9baad1b4f742b396e2fd1cdb2fea26c`
precedes the new client and harness, but not the existing provider. No fresh
production implementation or source recovery credit is claimed.

## Scope of the real component

`src/lib.rs` exports `keccak256` from its private `keccak` module and the
`ConnectionId` type from `context`. The actual operation returns
`ConnectionId::from_bytes([u8;32])`, which stores those bytes directly;
`as_bytes()` borrows the same array. No conversion, byte reorder, prefix,
network action, allocation, callback or configuration read is inserted in this
call path. Other modules implement separate node94 action-signable behavior;
their code is part of the actual Cargo graph but is not newly qualified here.

The existing test module additionally uses a compile-time `include_str!` of
`research/work-items/RE-005-action-signable-94/vectors.tsv`, outside the crate's
11-file directory. That immutable data input must be pinned and copied at its
real repository-relative location when building the unchanged test target.
The existing `tests/encoded-inputs.tsv` is inside the baseline crate. These are
historical node94 test inputs/answers, not the independent Visor oracle. The
client never reads either fixture and the harness never executes their original
generator, captured code, or a captured-instruction evaluator. Baseline test
success cannot substitute for the new 2,000-case supplied-byte comparison.

## Whole-message relation and bounds

The public input is an ordinary valid Rust byte slice. `chunks_exact(136)`
partitions it into complete contiguous rate blocks and a remainder of length
`t` in `0..135`, preserving order and every original byte, including NUL.
The initial `[u64;25]` state is zero. Each full block is absorbed into the first
17 lanes using little-endian eight-byte words, followed by one permutation.
`absorb` is called only on an exact 136-byte chunk or a local `[u8;136]`, so its
debug length assertion holds and each copied word is exactly eight bytes.
The zip/take loop writes only lanes `0..16`; capacity lanes `17..24` are not
directly XORed with input. This is the full-block invariant in the native proof.

The zeroed final 136-byte block receives the exact remainder, writes delimiter
1 at index `t`, and ORs 128 into index 135. When `t=135`, the result at that
byte is `0x81`; otherwise the two padding bits occupy separate bytes. The
block exists even for empty input and exact multiples of 136. Absorbing it by
XOR into the existing state is algebraically the same as the native tail XOR
followed by delimiter/final-bit XOR. It does not zero an already absorbed state.
One permutation follows. The first four lanes are serialized little-endian into
exactly 32 output bytes, matching the native finalizer's short output path.

All indices and loop counts are bounded by fixed arrays or valid slice chunks.
`t<136` justifies the delimiter write and remainder copy; 135 is in range.
There is no message-length multiplication, unchecked pointer arithmetic or
heap allocation in `keccak256`. Its fixed state/final block/output storage
requires an ordinary valid host frame, but no native stack/ABI equivalence is
asserted. The source uses u64 bitwise operations and rotates; no floating-point
control state, numeric overflow or subnormal policy participates.

## Permutation correspondence

The source represents lane `A[x,y]` at index `x+5*y`, the same little-endian
lane convention bound in the native proof. For each of the 24 recorded round
constants, it first forms all five column parities from the unchanged input
state. It computes `D[x]=C[x-1] XOR rol64(C[x+1],1)` and XORs D into all five
lanes of column x. Because column values are saved before updating state,
the in-place theta loop has no dependency on already modified lanes.

Rho/pi uses a carried lane rather than the native unrolled register schedule
or the independent oracle's 64 planes. Initially `carried=A[1,0]`. At each
iteration, `next=state[destination]` saves the next cycle input before its slot
is overwritten by the rotated carried value. The 24 `PI_LANES` destinations
are all distinct, nonzero and below 25. Their order is the coordinate orbit
`(x,y) -> (y,2*x+3*y mod5)`, starting from source `(1,0)` and returning to it
after 24 moves. The associated `RHO_ROTATIONS` are the triangular offsets
`(t+1)(t+2)/2 mod64`. Thus the carried value at each iteration is exactly the
original theta output of that orbit's source, and the write produces the
specified rho/pi destination. Lane zero remains unchanged by rho/pi.

Chi copies each five-lane row before updating it. The expression
`state[x,y] XOR ((!row[x+1,y]) & row[x+2,y])` therefore uses the row's original
rho/pi values for all five writes, with indices modulo 5. Iota XORs the current
round constant into lane zero only. The 24 source constants equal the pinned
native table and the independent LFSR-generated constants; this is checked as
a source-text/data binding in the admission audit. All rotations and lane-cycle
destinations are independently compared with the frozen coordinate certificate.
After each round the state is the same logical 25-lane state as the manual
native correspondence. Induction gives the complete 24-round relation.

This source argument is independent of test agreement. Tests and source-copy
mutants provide finite counterchecks of this relation and the harness, not a
universal CPU/compiler or constant-time/security proof. Native validity,
reader/import/error/cleanup preservation, byte-source provenance, normal return
and red-zone premises remain exactly those in the immutable pre-code proof.

## New qualification client

`input_client.rs` imports and calls the real public `keccak256` operation.
It accepts stdin only and no arguments. A request must have one LF-terminated
line, an opaque 24-digit lowercase hexadecimal ID, one tab and either `-`
for empty bytes or a nonempty even-length lowercase hexadecimal byte string.
Nibble parsing rejects non-ASCII, upper case, extra tab, CR and all other
non-hex characters. Duplicate IDs and missing LF are rejected. The ID is
used only for uniqueness and exact echo; it never selects an expected answer.

Each decoded byte slice is passed directly to the provider. The returned
32-byte array is printed as 64 lowercase hex digits, without truncation or
reordering. An output buffer is committed to stdout only after the entire input
has parsed and evaluated; malformed suffixes cannot publish a successful prefix.
Empty stdin produces empty stdout. Parser errors use exit 2 and stderr. These
are new qualification protocol policies, not native filesystem/error semantics.
Host input/output allocation and I/O must succeed; resource-exhaustion/service
behavior is outside this bounded client qualification.

Neither client nor provider reads expected streams, provenance labels, native
bytes, oracle code or official vectors. Only the build/comparison harness reads
expectations. The harness separately checks exact complete output streams and
retains actual compiler and client stdout/stderr. Compiled mutants must run the
entire 2,000-input stream with a value difference; build failures or panics do
not count as semantic kills. Until a separately bound source/build gate and
actual runs exist, all compilation, tests and mutant outcomes remain unclaimed.
