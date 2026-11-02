# Selected-caller parent slice: addressed manual proof

RE-013 / Visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

Conditional static proof for the selected caller state. Native exports,
addressed byte bindings and supporting abstract checks are reproduced separately;
their success does not mechanically prove the prose argument. No target execution,
instruction evaluator, host path API or filesystem observation is used.

## Question and explicit domain

The candidate asks which byte slice the `0x3a1780` caller passes to the
predicate and preparation calls. Its full returning P/Q allocation is a
different value, already bound by draft1375. The directory request policy in
draft1437 applies to this actual slice. The result below is restricted to the
iterator initialization performed by this caller, not every state admitted by
the three helper FDEs or an inferred standard-library/private Rust ABI.

Let B be the original n-byte candidate at nonzero p. Require n<=2^63-1,
nonwrapping readable immutable B, all actually accessed input/output/scratch
and active stack/return storage valid and nonaliasing, immutable code/data,
ordinary valid call/return state, normal callee-saved behavior and no concurrent
mutation. The formatter's allocation/copy/initialized-prefix premises remain
those of the credited prepared-path packet. The unqualified copied padding
bytes are not input to the selected predicates and are not asserted initialized
Rust values. They still require valid raw machine storage for their reads.

## Conditional result

Only slash byte 0x2f and dot byte 0x2e affect the component scan. No Unicode,
NUL, backslash, drive-letter or dot-dot cancellation is performed by that scan.
The UTF-8 admission below is separate and later.

Set m=n and R=(n>0 and B[0]==slash). Define the protected beginning L(m):
1 when R is true; otherwise 1 when B[:m] is exactly `.` or starts `./`;
otherwise 0. No input byte is read for m=0.

A suffix step, called only for m>L(m), finds the last slash at index k in
[L(m),m), if one exists. It yields component B[k+1:m] and consumes m-k
bytes, leaving m=k. Without such a slash it yields B[L(m):m] and consumes
m-L(m) bytes, leaving m=L(m). Classify empty or single-dot component as10,
double-dot as8, every other component as9.

First loop: take suffix steps until a tag other than10 is yielded, or no
suffix above the protected beginning remains. A yielded8/9 is eligible for
replacement. At exhaustion an absolute input yields tag6; a relative input
with a protected initial dot yields7 and removes that one dot; a relative
input without it yields10. Tag7 is also eligible,6/10 are not.

For eligible8/9, trim only trailing empty/single-dot suffixes of the remaining
prefix, again respecting L(m). A trailing8/9 is inspected without being
consumed. This produces U=B[:m]. For eligible7, U is empty. If the credited
validator accepts U, the temporary predicate/preparation slice is U;
otherwise it remains the original B. Noneligible6/10 bypass replacement and
retain original B. This distinguishes an empty eligible parent from the
no-parent bypass. Returned full P/Q storage is not truncated by this process.

## Native derivation: initialization and leaf

At3a1855/3a185a, the original pointer/length enter the iterator record;
3a185f writes tag6,+0x3a gets R at3a1864, and3a1868 writes word0x0201
to+0x38/+0x39, hence front=1/back=2. The second candidate repeats these
stores at3a1958..3a196b. The actual7e5ef8 binding selects694cf0.

The leaf678e70 receives output/count storage and the record. Front=1 means
the initial test at678e74 does not jump to678eab. R selects the protected
byte at678e81..678e93; otherwise678f27..678f7b tests exactly the relative
initial dot cases and sets offset1 or0. Its loop678ed0..678ee7 inspects
the original bytes backwards, starting at m-1, and stops before the protected
offset. RCX is decremented each iteration while RDX remains m; the read
`[rcx+rdx-1]` therefore addresses p+m-1,p+m-2,... . The loop counter R10
starts at the protected offset and reaches m after at most m-L steps.

On a found slash at k,678ee9..678eff sets component pointer p+k+1,
length m-k-1 and separator contribution1. Without one the pointer remains
p+L and component length is m-L. The stores678f48..678f55 return consumed
length=(separator?1:0)+component_length, tag at output+8, component pointer
at+16 and length at+24. The tests678f05..678f46 classify0/`.` as10,
`..` as8 and all other suffixes as9. For an admitted suffix step the count
is in[1,m-L], so subtraction cannot underflow, m decreases and the pointer
remains p. Panic/error blocks for inconsistent arbitrary states are outside
this selected, consistent initialization; they must still be retained as
native context and their unreachability justified by these inequalities.

## Native derivation: discard one semantic component

For front=1/back=2,694d38..694d52 chooses the R-specific corridor and
does not change front or p. The comparison with back3 and front>back cannot
reject these initialized bytes. In the absolute corridor694d60..694dc5,
m>1 calls678e70, copies its returned component record, subtracts the consumed
count and repeats exactly for tag10. m<=1 goes through695062/695067:
back becomes3,m decreases by1 and result tag6 is returned. The absolute
invariant m>=1 before that terminal step follows from the leaf bound.

The relative corridor694e9a..694f46 computes L from the current leading
bytes. For m>L it calls the same leaf at694ef9, subtracts the count at
694f23, writes the remaining length at694f2d, and repeats only for10.
Otherwise695015/69501a sets back3. Empty remaining input returns10 at
69501f..695022. A protected leading dot is removed at69504c..695056 and
returns7 at69505a. The selected relative suffix-step invariant ensures that
an exhaustion with m>0 is precisely the protected dot case; if no leading
dot is present the leaf consumes down to m=0.

The record's p/front/R are unchanged. On a yielded8/9 its back remains2;
on the special terminal6/7/10 it is3. Copied component payload/padding does
not overwrite the original iterator: output is a separate caller scratch
record under the nonalias premise. All tag10 loop backs strictly decrease m.

## Native derivation: trim the remaining prefix without discarding it

The actual7e5f30 binding selects678fa0. Its entry copies64 bytes locally.
The front trim678fd1..67904f executes only for front2, so it is unreachable
for this caller's invariant front1. At679053, back3 returns the current
pointer/length through6790ba/6791bd; this covers the already emptied tag7.
For back2,67905d establishes front<=1. Absolute remaining input uses
679061..6790b5 and only tests suffixes while m>1. Relative input uses
679118..6791b8 and computes the same protected dot offset; it only tests
suffixes while m>L(m).

The leaf writes a consumed count and tag into separate scratch. A tag other
than10 branches to6791ba before subtraction. For10 only,679098/6790f8/
679199 subtract its count and update the local remaining length; the same
positive-count bound proves termination. The stored original record is not
updated by this by-value trim.6791bd returns p in RAX and final m in RDX.
The other helper corridors for front>=2 or inconsistent records are retained
context, not claimed as recovered general iterator semantics.

## Native derivation: admission and use

3a187f..3a1888 implements an unsigned8 `(tag-7)<3` test, admitting exactly
7/8/9. Other tags retain original B.3a1895..3a1898 skips replacement for a
zero returned pointer; the stated nonzero-p domain excludes that case after
the pointer-preserving helper.3a18a2 uses7e4d28->49b560. Its strict UTF-8
result domain0/1, success original pointer/length and unchanged-input proof
are credited to accepted `RE-013-visor-child-args-utf8/PROOF.md`, not proved
again or awarded duplicate scan/byte credit here. Preserve its full memory,
stack/call and length domain as a prerequisite. A failing validator tag1
retains B. Success loads p/m at3a18af..3a18b4.3a18c9 and3a18ef use exactly
that temporary tuple. The repeated fallback corridor3a1982..3a19ee has the
same admission and selected-tuple behavior, with separate local destinations.

If original B is strict UTF-8, every produced prefix U is also strict UTF-8:
the possible truncation sites are0, the initial ASCII dot/root boundary, or
immediately before an ASCII slash. An ASCII slash/dot cannot be a continuation
byte of a multibyte encoding. This is an independent grammar lemma, not an
assertion that actual runtime G/X or every formatter input is valid UTF-8.
For arbitrary B, invalid removed filename bytes may leave a valid parent;
invalid bytes retained in the parent cause fallback to the full original B.
Embedded NUL is admitted by the validator; later path/OS rules are separate.

## Validation boundary

The retained exports include complete FDE/CIE and selected RELA/direct-call
records. The byte inventory freezes all873 retained instruction rows as identity
support, not873 separate semantic proofs. Below-image-identity controls reject
17 addressed instruction-byte corruptions and3 selected RELA-addend corruptions.
These check bindings, not the behavioral outcome of executing mutated code. A high-level byte-language model and independently formulated fixtures
can catch a mistaken theorem or normalization assumption, but are not a CPU
model and cannot establish the native transfer theorem by themselves.
No filesystem state/success, allocation safety, concurrency, original types,
full helper-state coverage or component gate is claimed.
