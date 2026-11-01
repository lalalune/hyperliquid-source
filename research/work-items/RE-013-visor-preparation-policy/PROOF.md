# Addressed preparation request and error policy

RE-013 / `visor`, capture SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Coordinates are linked ELF virtual addresses. The claim is
a conditional static request/error protocol, not filesystem success, execution,
complete parent-path grammar or original Rust equivalence.

## Domain and conclusions

Require valid stable nonaliasing input/options/output/scratch storage, an
ordinary callee-saved ABI and return slot, immutable admitted code/data and
no asynchronous mutation. The pointer/length values produced by the bound
component/slice helpers must be valid; the selected error representations must
support their observed reads. Allocators/copies must supply and preserve the
requested live storage. Cleanup, conversion, metadata, comparisons and other
opaque calls must return normally and preserve live values outside their
outputs. These are premises, not demonstrated helper/concurrency invariants.

Let K be the error-classification byte actually selected by the addressed
representation switch. Let D be the metadata predicate `tag != 2` and
`(mode & 0xf000) == 0x4000`. Let a mkdir request be failed exactly when the
import's returned EAX equals `0xffffffff`, as the machine code tests.

| Stage | Not failed | Failed, K=0 | Failed, K=12 | Other failed K |
| --- | --- | --- | --- | --- |
| First, ascending-parent search | begin reverse phase | advance to parent and increment saved count | begin reverse phase iff D; otherwise return original error | return original error |
| Reverse, saved-slice replay | continue replay | return error; no new parent search | continue iff D; otherwise return original error | return original error |
| Nonrecursive option arm | return zero | return encoded error | return encoded error; no D check | return encoded error |

On completed replay, or the explicit recursive empty/no-component paths,
normal return is zero. Zero alone therefore does not prove that a directory
was created, that any mkdir was requested, or that a later filesystem state
remains valid. A metadata failure does not replace the original mkdir error
with the new metadata error. A disappearing parent during replay does not
restart the first phase.

The selected callers store option word `0x1ff` and option byte +4 = 1, so
their relevant arm is recursive. The proof is about the actual input slice S
passed in RSI/RDX. It does not silently replace S with the full original P/Q
tuple from the prepared-path packet.

## Binding and option dispatch

Unique slot `0x7e5f50 -> 0x679ba0..0x67a9bf` binds the preparation body.
The temporary-path caller stores `0x1ff`/1 at `0x3a18d7/0x3a18df` and
calls at `0x3a18ef`; the second attempt repeats them at `0x3a19d6/0x3a19de`
and calls at `0x3a19ee`. The prefix selector stores them at
`0x4ac7a5/0x4ac7ad` and calls at `0x4ac7bd`.

Entry saves options RDI in R15 and length RDX in R12. The byte +4 test at
`0x679bba..0x679bbe` selects `0x67a28e` for zero (nonrecursive), otherwise
the recursive path. A recursive zero length branches at `0x679bc7` to
`0x67a3d1`, clearing R14 before the common return. Nonrecursive entry does
not take that early zero-length shortcut.

Both `0x7e5ef8 -> 0x694cf0` and `0x7e5f30 -> 0x678fa0` are actual bindings,
not guessed symbol names. Their full FDEs, last-component helper `0x678e70`
and comparison helper `0x68fd90` are retained as context. The recursive body
constructs records containing the actual input slice, a leading-slash bit,
tag 6 and state bytes 1/2. It compares component results against an empty
record and uses numeric tags 7/8/9 before taking another parent. We do not
claim a complete private iterator ABI, path-normalization theorem or recovered
grammar from these observations. The protocol below is conditional on the
valid slices/termination furnished by those helpers.

## Request encoding, first try and raw error representation

The direct mkdir slot `0x7e7be8` is GLOB_DAT symbol index 128, undefined
`mkdir`, addend zero. Slot `0x7e5900` binds `__errno_location`. This binds
the requested import names, not a particular runtime DSO/interposition or
actual syscall result.

For the first recursive request, lengths <= `0x17f` use a stack copy plus
a trailing zero (`0x67a04b..0x67a064`). A scan rejects interior zero bytes;
only a zero at index equal to the original length reaches `0x67a17c`.
The three short-copy scan replicas retain the scalar prefix, two-word skip
constants and scalar tail. Their no-zero skip uses the same base-256 borrow
lemma already proved in accepted `RE-013-visor-shell-nul-admission` (#1351):
the mask equality certifies no zero in the two inspected words, not an exact
zero-position mask. This packet rebinds the actual replicas and reuses that
credited lemma; it does not claim a new scan algorithm or rerun that packet's
different-provider receipts. Memory bounds and normal-copy premises remain.

At `0x67a17c..0x67a182`, RDI is the terminated copy, ESI is the options word
saved at -0x3c, and the call uses the mkdir slot. `0x67a188..0x67a19c`
clears R14 if EAX != -1 and transfers to the reverse-phase setup.
For EAX == -1, `0x67a1a1..0x67a1ae` loads a 32-bit word through the errno
slot, shifts it left 32 and ORs 2. Thus this normal arm carries the raw
representation `(uint32(errno_word) << 32) | 2`.

Interior-NUL rejection uses the address of the static error object at linked
VA `0x7dbb90`. Its low two linked bits are zero and its byte +0x10 is 20.
Under the stated aligned-load-bias/valid-representation premise, the selected
classification arm therefore reads K=20, outside both retry/metadata cases.
This is an object/field observation, not a recovered Rust error type.
Its raw first file word has a RELATIVE relocation to `0xbdeaf`; it must not
be interpreted as a loaded zero pointer.

## Long request adapter and credited NUL conversion

Lengths above 383 go through `0x663960..0x6639ff`, with callback pointer
`0x66bbe0..0x66bc10`. Slot `0x7e4c48` resolves to the previously qualified
converter `0x2bf100..0x2bf27a`. Under that prior packet's domain
`0 <= n <= 2^63-2`, storage/allocation/copy premises, it returns a terminated
copy with first-word `INT64_MIN` on zero-free input, or an error record for
an interior zero. Its finalizer `0x2bea00..0x2beae1` is retained context.
No source from the unlicensed inferred reference tree is used.

The adapter tests the sentinel through NEG/JNO at `0x663989..0x66398f`.
On success `0x663999..0x6639a2` passes the saved options context and copy
to the indirect callback. It saves the callback return, clears the copy's
first byte, frees its allocation when required, and returns the saved value
at `0x6639cd`. Error returns the static object above without invoking the
callback, subject to normal cleanup. Exception paths are not proved.

Callback `0x66bbe7..0x66bbef` follows the saved options indirection, places
its word in ESI and the terminated copy in RDI, then calls the same mkdir
slot. Its EAX==-1 branch creates the same errno encoding; otherwise XOR EAX
returns full RAX zero. These observations explain long-request return values
without invoking the capture, converter, callback or OS.

## First-phase classification and retry

The first error dispatch at `0x67a1d0..0x67a1e4` indexes table `0xbd100`
with `R14 & 3`. The exact four relative targets are `0x67a1e6`,
`0x67a20f`, `0x67a1ed`, `0x67a1fb`, respectively:

- tag 0 reads byte `[R14+0x10]`;
- tag 1 reads byte `[R14+0xf]`;
- tag 2 shifts the upper word into the argument of `0x68b5a0`;
- tag 3 clamps the upper word to at most 42.

The 122-entry table at `0xbd89c` is bounded by `dec edi; cmp edi,0x79;
ja default`. Raw input 2 maps to `0x68b5f9` (`xor eax,eax; ret`); raw input
17 maps to `0x68b5f0` (`mov al,0xc; ret`). Values outside the admitted table
index use `0x68b614` (`mov al,0x29; ret`). These are selected numerical
witnesses, not an assertion that K=0 iff the errno word is 2.

`0x67a214..0x67a216` tests K zero. Zero drops the error, increments the
saved count at -0x58, restores the precomputed remaining pointer/length
from -0x50/-0x168 and, if its pointer is nonzero, retries the first phase.
The parent helper result is therefore consumed conditionally; no actual
path grammar or alias/lifetime invariant is inferred from its pointer test.

Other K values reach the parallel table `0xbd110`, which selects the same
classification fields at different code sites. Only K=12 reaches the
metadata request at `0x67a447..0x67a455`, using the current slice.
Tag 2 drops the metadata error and returns the original R14 error;
otherwise the mode mask at `0x67a48a..0x67a49a` must pass before the
original error is dropped and reverse setup is reached. No new path creation
is inferred from this already-accepted metadata condition.

## Saved-slice replay and return cutset

The count accumulated only by K=0 failures controls allocation of count*16
bytes at `0x67a4b3..0x67a512`, with size/overflow checks. A second walk
starts from the original slice. For each required entry, `0x67a58e..0x67a59e`
stores its current pointer/length as a 16-byte pair, then advances via the
same component/remaining-slice helpers. Non-7/8/9 component results can set
the next pointer to zero; this is retained, not rewritten as a full filesystem
parent theorem. Storage/allocation/growth and helper consistency remain premises.

`0x67a6a9` constructs the one-past vector pointer. `0x67a6ca..0x67a6ce`
loads the preceding pointer/length pair. Each accepted request decrements
that pointer by 16 at `0x67a6c0`, so replay requests proceed in reverse
stored order. For an admitted sequence S0,S1,S2 with the first two attempts
classified K=0 and S2 accepted, the abstract request order is
S0,S1,S2,S1,S0. This is conditional ordering over supplied valid slices,
not a newly invented normalizer for original input bytes.

Short replay requests use mkdir at `0x67a809`; long requests use the same
adapter/callback at `0x67a8ec`. On failure the table at `0xbd120` classifies
the four representations at targets `0x67a85f/0x67a888/0x67a866/0x67a874`.
Unlike the first phase, it compares K directly with 12 at `0x67a88d`;
there is no K=0 parent-search branch here. Only D acceptance at
`0x67a8a4..0x67a8ce` drops the original error and resumes replay. Other
failures preserve that error, clean up the vector and reach the return.

After replay completion, `0x67a675..0x67a695` frees the vector when needed
and reaches `0x67a3d1`, clearing R14. The common ordinary return
`0x67a3d4..0x67a3e8` copies R14 to RAX and restores the frame. A failed
metadata check or other replay failure instead reaches this cutset with
the original nonzero error. Normal cleanup/storage preservation is required;
unwinding and arbitrary noncanonical pointer representations are excluded.

## Nonrecursive arm and scope limits

The separate zero-option-byte arm uses the same 383-byte stack/long split,
NUL rejection and mkdir import (`0x67a3c6`), then returns zero for EAX!=-1
or the packed errno error for -1. It does not perform the recursive early
empty-slice return or the K=12 metadata acceptance. It is retained so that
the actual callers' option-byte choice is explicit, not silently generalized.

Thirteen complete FDEs total 8,547 bytes. These include old caller,
converter/finalizer and metadata context; no recovered-function or new matched
byte credit is requested. Both native decoders must tile every range and
agree on every address/byte partition without masks. The checker binds the
manual argument inventory, three error representation tables, error-map data
and all selected relocations. Its 24+24 Boolean rows, request-order fixtures
and arithmetic/mutation controls support this manual argument. They do not
evaluate captured instructions or prove the opaque premises.

Exact temporary/parent-slice language, full iterator/allocator/error/metadata
ABIs, storage ownership, real mkdir/stat/errno behavior, race outcomes,
permissions/umask, process behavior, Rust reconstruction and whole-supervisor
equivalence remain open. All completion gates remain unchanged.
