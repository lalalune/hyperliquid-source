# Conditional metadata request/cache protocol

RE-013 / Visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Coordinates are linked ELF virtual addresses before load bias.
This is an addressed static argument, not execution, a CPU evaluator, an OS
capability test or recovery of a complete metadata/Rust ABI.

## Domain and precise outputs

The core FDE is689980..689c97. Require immutable admitted code/data and loaded
import bindings; valid ordinary x86-64 call/return state; nonwrapping valid
active stack, input pathname and at least0xb0 writable output bytes; valid
readable/writable cache byte and errno word; nonaliasing of those regions except
the intentional writes described below. Imported calls return normally and
preserve callee-saved registers, saved original-error storage and unrelated live
storage. Their requested output buffer and errno may change. Cache observations
at entry and after failed request are distinct sampled inputs; imported or
external activity may change the cache between those samples. No synchronization,
race freedom or final externally observed cache value is inferred.

Entry RSP is8 mod16. Push RBP and three saved registers followed by0x118-byte
allocation makes the vector-store frame valid/aligned under the stated premise.
The zeroed256-byte request buffer is T=[RBP-0x130,RBP-0x30). Saved error words
are at RBP-0x20 and RBP-0x28, outside T and the saved-register/return intervals.
Calls and their own frames must not alias live T, output or saved values. These
are explicit machine-storage premises, not inferred private Rust types.

Let C0 be the entry cache byte, C1 the byte freshly loaded only after a failed
main request, r0/r1 the low32 EAX request/probe returns, e0/e1 the sampled32-bit
errno words, and P(e)=(uint32(e)<<32)|2. A request is failed exactly when
EAX==0xffffffff; no claim about arbitrary high return bits is made.

| Selected condition | Output tag | Defined error at O+8 | Explicit cache store | Request count |
| --- | ---: | --- | --- | ---: |
| C0=2 | 3 | unqualified/untouched | none | 0 |
| C0!=2 and r0!=-1 | 1 | not an error field | 1 iff C0=0; otherwise none | 1 |
| failed main, C1=1 | 2 | original P(e0) | none | 1 |
| failed main, C1!=1, failed probe, e1=14 | 2 | original P(e0) | 1 | 2 |
| failed main, C1!=1, any other probe outcome | 3 | unqualified/untouched | 2 | 2 |

None/unqualified in the abstract support code is not a stored zero. For tags2/3
only the stated tag/error fields are qualified; success payload fields other
than the mode projection below remain outside the theorem. RAX as a function
return value is not qualified. All256 raw cache bytes are admitted, rather than
assuming a private enum restricted to0/1/2.

## Entry, dispatch and success

689993 samples cache7ee2b0.68999b tests exact byte2;6899a1 stores QWORD tag3
and6899a8 jumps to the epilogue. It makes no request and does not initialize
payload fields. The cache belongs to writable NOBITS .bss, recorded by the
collector. File section membership does not establish its runtime initial value.

6899ad..689a0a zero exactly T.689a11 tests the loaded optional pointer at
slot7e7f10. Its GLOB_DAT symbol is WEAK undefined statx@GLIBC_2.28. A nonzero
pointer reaches689a1f..689a32: RDI gets zero-extended entryESI,RSI gets entryRDX,
RDX gets zero-extended entryECX,RCX=0xfff,R8=T. The zero-pointer arm689b92..
689ba6 selects GLOB_DAT syscall via7e5490, with RDI=0x14c,R8=0xfff,R9=T
and AL=0; full entryRSI/RDX/RCX remain the intervening raw arguments. No loaded
pointer value, kernel implementation or libc behavior is inferred from the
symbol name or number. These are conditional argument requests.

689a38 or689bac tests EAX against-1. Success joins689a41. The saved C0 in
R14B is tested there: only zero stores byte1 to the cache at689a46. Other
nonzero entry bytes retain no explicit success-arm store. The output conversion
has no internal calls before its tag/payload stores.689b05 loads WORD T+0x1c
with zero extension and689b0c writes DWORD O+0x38.689ae2 writes QWORD tag1.
The other copy/arithmetic stores are retained native context; do not call their
payload a proved deployed stat struct or assume all padding initialized.

## First failure, fresh cache sample and separate probe

689bb5 calls __errno_location at7e5900; the returned word address is retained
in R14.689bbe..689bc9 samples e0, constructs P(e0), retains it in callee-saved
R15 and stores it locally.689bcd then samples C1. Exact1 at689bd4 branches
to689bd8/689bdf, writing QWORD tag2 and P(e0). That branch does not probe or
write the cache. Equating C1 to C0 requires an additional no-intervening-write
premise and is not needed by this theorem.

If C1!=1,689be8 tests the same immutable optional slot again. The statx probe
at689bf2..689c00 has RDI=0,RSI=0,RDX=0,RCX=0xfff,R8=0. Its syscall alternative
689c0d..689c23 has RDI=0x14c,RSI=0,RDX=0,RCX=0,R8=0xfff,R9=0,AL=0.
No live probe, syscall, pathname lookup or filesystem query was performed.

A probe EAX!=-1 reaches689c58 directly. Failure reaches689c2e, which samples
e1 from the retained errno pointer and constructs a separate P(e1) atRBP-0x28.
Its address is supplied to65f260 at689c44. At689c49 the retained e1 inR14D
is compared to exact0x0e. Equality stores cache1 at689c4f and jumps to the
original-error return689bd8: O+8 is still P(e0), never P(e1).

Other probe outcomes store cache2 at689c58 and tag3 at689c5f, then pass the
saved P(e0) address to65f260 at689c6a. O+8 is not written on this tag3 path.
Thus a successful availability probe does not take the tag2 preserving branch,
and a failed first request alone does not imply a stat64 fallback or a numeric
kernel capability result. The numeric14 comparison is retained without an
unverified deployed-ABI errno name.

## Credited cleanup dependency and termination

Accepted base packet `RE-013-visor-descriptor-wait/PROOF.md` section4 already
proves the specific low-tag cleanup route at65f260..65f32e. Reuse and credit
that outcome. Every locally constructed P(e) has low bits2.65f26b..65f279
reads the valid local word and branches to65f280..65f288, restoring its frame
and returning without pointer/heap callbacks or result-region writes. New and
original packed words therefore leave R14/R15 and the output/cache fields
intact under ordinary call/stack premises. This closes the used cleanup route;
the retained heap-tag and unwind paths remain outside the new proof.

The core's selected ordinary CFG is acyclic after treating normally returning
calls as call boundaries. Backward numerical jumps to the success writer or
original-error writer lead to the epilogue, never to another request decision.
At most two main/probe requests occur; no local retry loop is inferred. No
process termination, exceptional unwind or imported-call totality is claimed.

## Conditional wrapper projection, after separate pathname admission

Full context686d10..686f28 is retained from1437. Its pathname copying/NUL scan
and long-path663760/696e00 admission are not newly proved here. Composition is
conditional on reaching686e48 with a valid admitted C-string. This caller supplies
RSI=0x00000000ffffff9c (signed low32 descriptor-100),RDX=pathname,ECX=0.

It compares the helper's output tag at686e4d. For a non3 result,686eeb..
686efa copies0xb0 bytes into the final output. Tag1 therefore carries the
zero-extended mode word at final+0x38; tag2 carries the original helper error.
This raw copy does not qualify padding or unknown payload fields.

For3 it zeroes a0x90-byte buffer and calls the imported stat64 at686e9e.
EAX==-1 at686ea4/686ea7 samples a new errno at686f02..686f0e and returns
tag2 with that **later stat64 error**, not the earlier helper error. Success
copies0x90 bytes to final+0x20 at686eb9 and stores tag0 at686ebf. Final mode
field+0x38 thus projects that buffer's DWORD+0x18. The shared directory-mode
mask can be interpreted over these raw words only under its separately bound
caller predicate; no actual file type or OS struct ABI is established.

## Evidence and practical limits

Native exports retain the three complete FDEs, CIEs, called/imported slots,
optional weak-symbol record, global writable .bss bounds and referenced error
object context. The new outcome is the request/cache/probe relation and its
bounded composition. Cleanup and wrapper ranges are credited/reused context;
no new recovered-function/byte count, component gate or Rust-equivalence claim.
Abstract decision tables, integer projections and byte-binding corruption
controls support this written proof, not execute captured or mutated code.
Actual runtime cache observations, loaded import availability, metadata contents,
path admission outside the selected boundary, filesystem effects, concurrency,
exceptional paths and complete payload ABI remain unproved.
