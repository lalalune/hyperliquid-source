# Complete static UTF-8 proof for the used visor child-argument stage

This is an explicit static block/cursor/memory proof for the fixed captured
artifact, bound by the collector to every instruction and edge. It is not a
general automated machine-equivalence verifier or a dynamic target comparator.
Independent review of every block transfer and the induction is required before
publication. Codec comparison supports the separate high-level model only.

Validator [0x49b560,0x49b757):503 bytes, 143 instructions, 48 branches, 57 basic
blocks, one local RET and no calls. The three unreachable padding instructions
are retained and classified. Adapter [0x48dc00,0x48dc43):67 bytes, 15 instructions,
four blocks, two calls and one branch. Error-helper fallthrough 0x48dc43 is open.
Target SHA-256 89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31.

## Conditional validator contract and its domain

Let p=entry RSI, n=entry RDX, q=entry RDI, and B the immutable n-byte input.
Require: 0<=n<=2^63-1; for n>0 the complete nonwrapping address interval
[p,p+n) is readable and immutable; q..q+24 is nonwrapping writable memory.
Let S be validator-entry RSP. The complete active frame/return interval
[S-24,S+8) is nonwrapping and valid: pushes write/save[S-24,S), RET reads
[S,S+8). The output interval must be disjoint from that entire interval,
and B must be disjoint from both q..q+24 and the active frame/return interval.
This explicitly excludes q=S (which would overwrite the return address) and
input bytes overwritten by register saves. Code, table and selected relocated
bindings are immutable and match the authenticated capture. Result and active
stack writes must be disjoint from all these immutable image regions. Ordinary
valid call/return-state contents are assumed separately; readable stack memory
alone does not establish a valid hardware return target. Empty n=0 requires
no readable input byte. These are explicit machine-memory/call conditions,
not recovered Rust types or a private ABI.

For the used adapter at entry RSP=Sa, q=[Sa-24,Sa); CALL's return slot is
[Sa-32,Sa-24); validator saves occupy[Sa-56,Sa-32); adapter RET reads[Sa,Sa+8).
Require nonwrapping valid stack storage and B disjoint from this complete
[Sa-56,Sa+8) interval. The element descriptor's pointer/length fields are
readable before the call. Unknown error-helper stack/memory effects are
excluded after its call boundary; no post-error-helper input-preservation
claim is made.

The complete static argument below is for this fixed artifact and explicit domain. Its endpoint is finite arrival at local RET 0x49b756 with the defined protocol; actual hardware return additionally assumes ordinary valid call/return-state contents. The resulting protocol is:

- Success iff B satisfies the strict UTF-8 byte grammar below. The defined
  output fields are qword[q]=0, qword[q+8]=original p, qword[q+16]=original n.
  RAX remains q. B is unchanged under the nonalias assumption.
- Failure has qword[q]=1, qword[q+8]=i at the first invalid/incomplete sequence
  start. Byte[q+16]=0 for an incomplete sequence at the end; byte[q+17] is
  then unqualified. Otherwise byte[q+16]=1 and byte[q+17]=1,2 or3 according
  to the observed invalid-span protocol. Bytes[q+18..q+23] are unqualified
  on failure. This is a raw tag/field protocol, not a private Rust enum layout.
- No calls occur in the validator. Total normal execution on this domain
  needs the explicit cursor/phase progress argument, not only a local RET.

The grammar is ASCII 00..7F; C2..DF followed by 80..BF; E0+A0..BF+80..BF;
E1..EC/EE..EF followed by two80..BF; ED+80..9F+80..BF; F0+90..BF+two80..BF;
F1..F3 followed by three80..BF; F4+80..8F+two80..BF. Other leads fail.
Embedded NUL is ASCII at this stage. This does not establish OS/process or
public CLI acceptance of an argument containing NUL.

## Complete invariant obligations tied to actual blocks

**I1 — body/control closure.** Authenticate one immutable full-target byte
snapshot. FDE endpoints, every decoded byte and adjacent-row tiling must agree.
Derive all 48 branch destinations from actual displacements, every block's
successors and predecessors, the sole RET and three unreachable padding nodes.
Every one of 57 blocks must have a checked semantic transfer. Unknown instructions,
extra edges/calls or unclassified blocks block the whole-predicate claim.
No concrete x86 interpreter/emulator is proposed.

**I2 — persistent registers and frame.** Entry saves q in RAX, computes
T=max(n-15,0) in RDI via unsigned subtraction/CMOVAE, and preserves p in RSI
and n in RDX. Nonempty setup computes a=(-p) mod 8 in R8, initializes RCX=0,
sets the actual table base and mask 8080808080808080. All later writes to
these persistent variables must be audited; RAX=q and RSI=p/RDX=n remain
unchanged until defined result stores. Only stack saves/restores and the
terminal q-region stores write memory. No input mutation can invalidate a
previous byte fact under the explicit nonalias/immutability conditions.

**I3 — main cursor/prefix.** At0x49b5a6 and0x49b5af, 0<=i<=n, RCX=i, B[:i]
is valid UTF-8 and all previous chunks/codepoints are complete. The load at
0x49b5af has i<n. Every cursor write in the whole body is classified: RCX=0
initially; full 64-bit INC/ADD16 in ASCII; MOV RCX,R14 at the multibyte join;
and terminal protocol overwrites after no further reads. Low32 arithmetic
is used only for the alignment residue, never as the actual address cursor.

**I4 — ASCII alignment peel.** A nonnegative loaded byte is00..7F. The
(R8D-ECX)&7 test is exactly (a-i) mod 8 even for i above2^32; truncation does
not affect low3 bits. If nonzero, the already checked ASCII byte advances
full RCX by 1 and returns to the cursor guard. Input pointers need not be
assumed aligned initially.

**I5 — 16-byte ASCII loop.** A wide read occurs only when i<T. For n>=15,
i<n-15 implies i+15<n; for n<15, T=0 and no wide read occurs. Two8-byte
loads cover precisely B[i:i+16]. (word0 OR word1)&8080...==0 iff every one
of those 16 bytes has high bit 0. Its backedge adds exactly16, preserves the
valid prefix and i<=n, and strictly decreases n-i. The alignment test governs
entry, but x86 unaligned-load behavior is not used as a hidden bounds excuse.

**I6 — ASCII tail and phase handoff.** The tail reads only while i<n.
Nonnegative bytes advance i by 1; the final increment reaches exactly n.
A negative byte returns to the main load at the same i, which immediately
selects multibyte decoding. A zero-progress cycle is impossible with immutable
input: without a previous bulk advance the ASCII entry already knew B[i]<80,
so the tail must advance; after a bulk advance n-i already decreased. A tail
handoff at B[i]>=80 cannot select the ASCII phase again. This closes the
otherwise misleading same-cursor backedges as well as all finite scan loops.

**I7 — lead classification.** Read and retain all 256 actual table entries.
ASCII dispatch bypasses the table. For80..FF, the actual width table permits
C2..DF=>2, E0..EF=>3, F0..F4=>4; all others=>0 and the invalid-width route.
The default error-presence byte is set to1 before this dispatch, overriding
R9's earlier ASCII scratch value. Each width's guards must be verified in
control-flow order; table entries alone do not prove the accepted grammar.

**I8 — multibyte bounds and predicates.** Each load at i+k is preceded by
its exact i+k<n guard. The n<=2^63-1 domain prevents the +1/+2/+3 arithmetic
from wrapping. Actual signed8 comparisons derive80..BF from <=BF or <C0,
ED second80..9F from <=9F, F4 second80..8F from <=8F. E0 uses
(second&E0)==A0; F0 uses ((second+70) mod256)<30. The generic lead tests
select E1..EC/EE..EF and F1..F3 after the special cases. All12 extracted
finite predicates have been enumerated over all 256 byte values and match
those independent intervals (`record.json` → `finite_predicate_support`), but this
is support for I8 only, not proof of I1-I13.

**I9 — multibyte join/progress.** The only incoming branches to0x49b5a0 are
successful2-/3-/4-byte continuations. Their R14 is respectively i+1, i+2,
i+3; the join increments R14 then copies it into RCX, yielding i+width.
The checks ensure the last consumed index<n, so the new cursor<=n and the
extended prefix remains complete valid UTF-8. R14D's temporary second-byte
value is replaced by a fresh index before any successful join.

**I10 — first-error protocol.** Invalid lead/second byte enters width 1;
invalid third enters width 2; invalid fourth enters width 3. RCX stays at the
sequence start across these branches. Truncation clears R9D and does not
qualify BL, so its written byte17 must not be treated as a valid count.
Every nontruncated failure is dominated by R9B=1 and an explicit width 1/2/3
assignment. The common error writer stores prefix, flag, conditional width
then sets RCX=1 for the tag store. An invalid present byte is checked before
later missing-byte guards: e.g.E0 80 is invalid, while E0 A0 is incomplete.
The model must preserve this ordering.

**I11 — success/completeness/termination.** Empty input goes straight to
success with original p and zero n. Other success predecessors are cursor>=n
under i<=n, or an ASCII tail that just reached n. Result fields are the
original p/n and tag0; failure fields are only those in I10. I3-I9 establish
valid-prefix induction; every standard-valid next codepoint takes its success
join, and every nonstandard/incomplete next codepoint takes I10. Combined
with the finite-progress argument this yields iff, not merely no false positives.
Together I1-I10 and this induction establish the stated local-RET protocol under the domain. Codec examples do not establish this target result; the complete block reasoning and independent review are required.

**I12 — actual adapter boundary.** The67-byte adapter reads an element's
pointer/length from+8/+16, passes its stack result region through the actual
RELATIVE slot0x7e4d28->0x49b560, then compares the returned tag with1.
Given the validator's proved tag domain0/1, its local RET returns the same
valid input pointer/length. Error tag 1 supplies the exact 35-byte diagnostic
and Location to0x7e4cb8->0x49ab50. The external error helper's effects and
the open fallthrough at0x48dc43 remain unqualified. In particular no panic,
process termination or global rejection theorem is inferred from its name.

**I13 — used child-argument value.** Revisit only the existing #988 descriptor
binding0x7e6aa0->0x48dc00 and selected collection call sites0x61da34/0x61db8c.
Preserve ordinary normal-call/callee-saved/valid-stack assumptions explicitly.
Do not reinterpret the whole 860-byte collection's ownership, allocation,
count/order or private vector layout. The contribution closes checked
byte-span adaptation, not a public accepted-CLI or spawn policy.


No original Rust function/type boundary, process termination, public CLI grammar, binary-equivalence or component gate follows from this conditional result.
