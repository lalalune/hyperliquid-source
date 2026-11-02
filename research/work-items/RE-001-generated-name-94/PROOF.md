# Static generated-name argument

Addresses are ELF virtual addresses in the node94 digest in README.md. This
argument uses retained complete disassemblies, not capture execution or an
emulator. Assume valid thread-local state and helper arguments, stable readable
formatted bytes, normal helper returns, and successful disjoint allocation for
positive lengths. For the copy proof, 0 <= n < 2^63 and valid source/destination
ranges do not wrap. These assumptions are not a recovered public Rust ABI.

## Thread-local word and refill requests

At `0x144adae`, FS:-0x4a0 is compared to 1. Equality takes the pointer-slot
address FS:0 minus 0x4a8; otherwise `0x144b0be` calls `0x4e12f10` with that
address and ESI=0. A nonzero return rejoins the slot load; zero requests the
failure helper `0x4eeb8c0`. The loaded state's first qword is incremented;
a zero result goes to UD2. The normal return decrements the same qword and
calls `0x4e13590` when it reaches zero. This suggests reference-count-like
ownership, but the Rust type and helper contracts are not established here.

Let S be the loaded state, i = qword[S+0x110], B = qword[S+0x158],
G = qword[0x5788420], and H = qword[S+0x160]. The observed normal request
selection is:

| Condition | Request and local update |
| --- | --- |
| unsigned i < 64 | No refill request; retain i |
| i >= 64, signed B > 0, SF64(H-G)=0 | Store B-256 at S+0x158; call 0x4e14560 with RDI=S+0x120, ESI=6, RDX=S+0x10 |
| i >= 64, either test above fails | Call 0x4e13420 with RDI=S+0x120, RSI=S+0x10, RDX=G |

After either refill's normal return EAX is set to zero. At `0x144ae3a` the
routine loads one DWORD at S+0x10+4*i, increments i, writes S+0x110, and saves
the DWORD for formatting. Thus the visible consumer reads one 32-bit word;
post-refill it reads index 0 and stores 1. The called helpers may have further
state effects; their RNG, reseed and entropy contracts are not proved here.

`SF64(H-G)` means the high bit of the 64-bit wrapped difference. At
`0x144ae0f` the branch is **JS**, not JL. For example H=0 and G=2^63 gives
SF=1 although signed H is not less than signed G; H=2^63 and G=1 gives SF=0
although signed H is less than signed G. No ordering or generation-age
interpretation is substituted for this predicate. B is tested before the
256 subtraction, so even B=1 requests the first helper and stores -255.

## Formatting arguments and callbacks

After saving the word, `0x144ae55` requests `0x151cba0` into a stack value.
Two consecutive (value pointer, callback) pairs are then constructed:

1. That value with callback `0x1454ad0` through RELATIVE slot `0x576f528`.
2. The saved DWORD with callback `0x15708b0` through slot `0x576eb48`.

The shared formatter `0x1344760` receives descriptor `0x1e84e2`, whose exact
five bytes are `c0 01 5f c0 00`. The literal underscore and argument ordering
are bound; the descriptor alone is not a proof of the complete rendered name.
The labels "time" and "word" describe the observed caller roles, not symbols
recovered from a source build.

The first callback's complete 72 bytes establish this request order:

- Call `0x151f240` with the original value and formatter. Nonzero low AL
  returns low AL=1 immediately.
- Otherwise load the formatter's +0 data and +8 vtable, pass ESI=0x20 to
  `[vtable+0x20]`. Nonzero low AL again returns 1.
- Otherwise tail-call `0x15204a0` with value+4 and the original formatter.

This proves a space-code request between two helper stages, with short
circuiting. The actual virtual callback and complete stage output remain open.
Only low AL is promised on the early return; upper return bits are not fixed.

The second callback loads a **DWORD**, passes it with a ten-byte stack buffer
and EDX=10 to `0x15702c0`, then requests `0x15723b0` with ESI=1, EDX=1,
ECX=0, R8=buffer+returned_offset, R9=10-returned_offset. That arithmetic is
observed; validity of the returned offset, exact digits and padding depend on
unrecovered helpers. This packet does not claim a complete integer formatter.

## Copy and exact byte replacement

The formatter returns three words; the third is treated as length n and the
second as source pointer P. A set sign bit in n takes an error request and
UD2 path. n=0 selects pointer 1 without allocation and writes (0,1,0).
For positive n, allocation `0x54c06b0` is requested with size n. A null return
takes the error path. Let D be a successful returned pointer.

Vector copying is admitted at `0x144aece..0x144aee4` only if n>=8 and
unsigned `(D-P) mod 2^64 >= 32`. This packet proves the copy for valid
disjoint allocations, not arbitrary overlapping memory or malformed pointers.

For a byte x, PCMPEQB against 0x20 yields m=0xff if x=0x20, otherwise m=0.
The PANDN/PAND/POR sequence computes

`((~m & 0xff) & x) | (m & 0x5f)`.

Therefore its result is 0x5f exactly when x=0x20 and otherwise x. The 16-lane
constants at `0x2092e0` and `0x206b60` are all spaces and underscores. The
eight-lane constants at `0x208c50` and `0x205dd0` have those bytes in the low
eight lanes and zeros in the high lanes; only the low eight lanes are stored.
The scalar CMOVE sequences select the same 0x5f after comparison with 0x20.
No other byte changes: tab, newline, slash, NUL and non-ASCII bytes are not
removed or escaped by this copy. Length is preserved; filename safety and
text encoding are not established.

## Coverage of every byte

For the vector-admitted path let a=32*floor(n/32) and b=8*floor(n/8).
Since n<2^63, masks `0x7fffffffffffffe0` and `0x7ffffffffffffff8` compute a
and b exactly.

- If n>=32, the two 16-byte operations at `0x144af30` copy each 32-byte group
  partitioning [0,a). The loop increments by 32 and stops exactly at a.
- If n<32, the cursor starts at 0. Otherwise bits 3 or 4 of n determine
  whether at least one eight-byte group remains after a. Those groups copy
  [a,b), increasing by eight. If b=n, the routine exits directly.
- Scalar handling starts at b (or at 0 when vector admission failed). This
  starting cursor c is a multiple of four. The byte loop first copies n mod 4
  bytes. The remaining length is divisible by four, and the four-byte loop
  partitions that remainder until its cursor equals n.

For the scalar loop gate, RCX still holds the *pre-byte-loop* cursor c when
`c-n` is compared unsigned to `2^64-4`. Scalar entry has c<n. Under these
conditions JA exits exactly when n-c is 1, 2 or 3, all already handled by the
byte loop. Otherwise the four-byte loop handles the rest; there is no zero
remainder entry case to misinterpret. Early exits at a=n or b=n prevent it.
The paths cover [0,n) without gaps, duplicate writes or out-of-range loads.

`coverage.py` checks the lane identity for all 256 byte values and the partition
for all 4,097 lengths 0..4096 under both copy-mode possibilities: 8,194
configurations and 16,781,312 (mode,length,position) entries. It additionally
checks the SF/OF identity over 64 boundary pairs and retains counterexamples
to substituting signed comparison. These are finite arithmetic checks of this
argument, not executed target fixtures or an unbounded machine proof.

## Output, extent and remaining gaps

At `0x144b07f` the normal result stores `(n,D,n)` at output+0,+8,+16;
RAX eventually returns the output object's pointer. The original formatted
buffer is passed to `0x54c8cb0` when its first word is nonzero, using that word
as RSI and EDX=0. The ownership interpretation is limited to these requests.
The complete bodies include exceptional cleanup, but LSDA landing-pad
ownership, unwind behavior and failure-helper contracts are not closed.

All local branch destinations are instruction boundaries in the retained FDEs;
GNU and LLVM agree on all bytes and instruction starts. Call records preserve
all explicit calls and the indirect tail jump. PLT unwind calls and the
register-indirect formatter callback remain qualified gaps. No full function,
RNG, formatter, filesystem, Rust-build or runtime-equivalence claim follows.
