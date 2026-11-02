# Conditional ordinary-return proof

All addresses are linked virtual addresses in the one captured Visor
SHA25689338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31.
This is a conditional value/ownership argument, not captured execution,
source-name recovery, a complete shell implementation or a real-time guarantee.
The original all-input duration proof and source qualification are credited
through DEPENDENCY-PINS; their bytes and historical records remain unchanged.

The complete core extents are42a290..42a4c2,3d8af0..3d8bf0,
3f5ca0..3f5d0e and3f5f40..3f5fe7:1,095 bytes/291 rows.
The two duration bodies and four runner/format/GPG contexts are retained
separately. All ten complete GNU/LLVM byte partitions total7,949 bytes/1,694
rows. CIE/FDE extents and65 LSDA call-site rows bind coordinates; no exception
action or rollback theorem follows from that table.

## 1. Required domain and observations

Model an attempt as the supplied composition A(R)=runner3d8d70(R,L),
where L is the fixed relocated record7b30c0. Its bytes bind the17-byte
base/src/shell.rs literal, raw fields49 and32. These are observed constants,
not an original Rust Location type or original compiler identity. A zero
return is the protocol's success variant. A nonzero return supplies an owned
error handle with a valid first-word vtable and normally returning destructor.
The helper's preflight and error constructors remain opaque, so zero is not
universally interpreted as proof that an external command succeeded.

The request, selected delay slice, description, error handles, terminal result,
format temporaries and live native frames must be valid and noninterfering as
specified below. Pointer addition must not wrap. The delay slice has canonical
8-byte elements and a realizable valid extent; no arbitrary-u64 pointer/count
theorem is claimed. Opaque helpers preserve borrowed values and the explicitly
retained locals/registers. Callee-saved registers obey the admitted calling
convention. Allocation succeeds with valid ownership, and every called
destructor returns normally while preserving the next live result.

The duration dependency returns a canonical pair(S,N) with0<=N<1e9 under
its original float/environment/loader/frame premises. Its value semantics
apply to every raw64-bit input; this source plan will use its unchanged
integer implementation. Native floating exceptions/flags are not newly
qualified here.

Model the sleeper as the supplied imported call with raw clock1, flags0 and
one address used for both request and remaining output. The external ABI
must permit that alias. Code0 reports completion; all remainder bytes are
ignored. Code4 supplies a canonical pair(r,n) with0<=r<=INT64_MAX,
0<=n<1e9 and(r,n) lexicographically no greater than the requested pair.
Finite callback returns and finitely many interruption replies are separate
termination premises. No elapsed-time or scheduling fact follows.

The terminal builder is the supplied composition of formatter2bebb0 and
the two final constructors. It borrows description, the complete original
selected raw-bit list and last error, produces a valid independent owned
terminal value, and leaves the last error alive until the caller destroys it.
The terminal value and its owned payload survive that destruction. This
noninterference premise matters: merely storing a pointer to last-error
storage and then destroying that error would not justify a safe result.
No exact floating/error diagnostic rendering is asserted.

## 2. Entry, schedule selection and laziness

The six pushes and sub0x88 at42a290..42a29a reserve the local frame.
The request is saved atB+0x28, description pointer/length atB+0x60/+0x68,
and incoming schedule pointer/count inR14/R12.42a2bd calls A before
examining the schedule. At42a2c3..42a2c6, zero reaches42a2ed, clearsR14,
and jumps to the sole ordinary epilogue42a45e. It cannot read an element,
invoke a sleeper/final builder or drop an error on that path. Therefore
unused schedules and callback replies cannot be eagerly interpreted by
a corresponding source operation.

For a nonzero initial result, RBX and[B] hold the current error.42a2cf
tests the schedule pointer, not its count. A null pointer reaches42a2f5:
the selected pointer is7c650 and selected count3. The incoming count is
irrelevant on that arm. The exact selected words are
3f50624dd2f1a9fc,3fa999999999999a,3ff0000000000000. Under the credited
conversion contract they produce1,000,000ns,50,000,000ns and1second.

A nonnull pointer is saved unchanged atB+0x18, with its original count
atB+0x20. Count0 branches directly to42a3e9; it differs from null/default.
Otherwise42a2e7 forms pointer+8*count and42a311 saves that end atB+0x10.
Under the valid nonwrapping slice premise, every subsequent increment
advances by one element and equality with that end exactly detects
exhaustion. The saved original pointer/count are never advanced.

## 3. Delay conversion, chunking and interruption

At42a330 exactly the next selected raw word is loaded intoXMM0.
42a335 calls330360 through the unique RELATIVE slot7e53c8. RAX is
copied toR12 before AL is reused. The tests42a33e..42a34b skip sleeping
exactly when returned seconds and EDX nanoseconds are both zero.
The next attempt still occurs on this zero-duration arm.

For a nonzero pair, mov eax,edx at42a34d zero-extends the nanoseconds.
The constant loaded at42a316 is INT64_MAX.42a350 compares remaining
seconds unsigned, and cmovb42a356 selects q=min(S,INT64_MAX).
Stores42a35a/42a35f write(q,N) intoB+0x30/+0x38.42a364 retainsS-q.
The call42a374 usesR15 loaded from7e6628, whose dynamic symbol is
clock_nanosleep, with EDI1, ESI0, RDX=RCX=B+0x30.

For returned code0,42a37f zero-extends EAX0; therefore test42a381 and
jle42a384 necessarily choose42a3a8. The syntactic42a386 backedge is
not a feasible zero-return continuation under these instructions.
The remainder fields are not loaded on this arm. If unrequested seconds
remain, the next iteration has nanoseconds0; otherwise it advances.

For a nonzero code,42a390 compares the raw32-bit code with4. Only4
loads the remaining structure:42a399 adds its seconds toR12 and
42a39e loads its nanoseconds intoRAX. Positive nanoseconds branch back
at42a3a6; otherwise42a3a8 checks remaining seconds. Under the canonical
domain, nonpositive nanoseconds means exactly zero. Both components
zero advance, and either positive component repeats.

The arithmetic is exact over the admitted domain. Since0<=q<=S,
S-q does not underflow. Since0<=r<=q, (S-q)+r<=S<=u64_MAX,
so add-back does not wrap. Nanoseconds are a canonical remainder;
they are not added to unrequested seconds. Equivalently, let
T=1e9*S+N and Q=1e9*q+N. Completion replaces T by T-Q.
Interruption replaces it by T-Q+(1e9*r+n). This independently stated
integer-total recurrence gives exactly the same sequence of requests.
A zero remainder may complete the current sleep immediately. A remainder
equal to the request may make no progress; termination therefore requires
the finite-interruption premise, not just the nonincrease inequality.

The unchanged converter's largest seconds output is2^64-2048, from the
largest positive representable input below2^64; its larger-input plateau
is much smaller. Thus at most two successful chunk completions are needed
without interruptions. This is a corollary of the credited conversion
partition, not new duration-byte credit. Interruption counts are unbounded.

Any nonzero code other than4 reaches42a473..42a490: the actual code
addressB+0x0c and fixed comparison/location arguments are supplied to
65fb4a, followed byUD2 if it returns. This has no ordinary return in the
selected function. A safe source refusal here is new policy. Likewise,
negative/noncanonical/oversized code4 remainders are outside the theorem:
for example, with no retained seconds, native negative remaining nanos
can take the nonpositive branch and proceed, while a safe source may
refuse. Never silently extend the canonical theorem to that input.

## 4. Attempts, error replacement and exhaustion

After each completed or skipped delay,42a3ad restores the original request
pointer and42a3b2 restores the same locationL.42a3b9 invokes A.
On a nonzero return the new error is placed inR12 before the old
RBX error's first vtable entry is called at42a3d1. Only after that normal
drop does42a3d3 advance the pointer and42a3d7/42a3db install the new
current handle. The valid frame and destructor-preservation premise
protects the new handle across that call. This is creation-before-drop,
not drop-before-attempt or drop-before-replacement-creation.

On a zero attempt return,42a453 clearsR14.42a456..42a45c destroys
the current error, then42a45e returns zero. Initial success has no such
drop because no current error was created. By induction after k failed
attempts, the first k-1 error handles have been destroyed in order and
exactly the kth remains current; it stays alive during all intervening
conversion/sleep/next-attempt calls.

On exhaustion,42a3e9..42a424 prepares three two-word borrowed formatter
arguments: description addressB+0x60 with32cf10; original slice
addressB+0x18 with32c6d0; current-error-handle addressB with2c08e0.
The latter is the address of the local handle, not the error pointer
itself.42a429 supplies the complete54-byte token stream at6aa7b.
42a43a calls2bebb0 with the24-byte output atB+0x70 and the argument
arrayB+0x30..B+0x60. It must not destroy the current error, mutate the
selected list or corrupt the saved handle/request/description.

42a445 passes that output to3f5ca0, saves the returned final pointer in
R14, reloads the last error from[B], then drops it at42a45c. The final
result survives in a callee-saved register and is returned unchanged.
The whole selected list, rather than only the unconsumed tail or the last
delay, reaches the terminal builder.

## 5. Nonzero final error and ordinary owned caller

3f5ca0 saves the input string's first two words, invokes675690 with a
48-byte output at its local+0x30, copies those48 bytes to local0,
and passes the original24-byte string and copied context to3f5f40.
The context helper's valid initialized output and preservation are premises.

3f5f40 builds an80-byte record: vtable7b12b8 at+0, context at+8..+56
and owned string words at+56..+80. It requests80 bytes through slot7e4b60
bound to70bf30. Null branches at3f5f89 to2beae1 with alignment8/size80
and thenUD2. A nonnull valid allocation receives all80 bytes before the
ordinary ret3f5fbb. Thus every admitted ordinary final-factory return
is nonzero. No allocator failure, backtrace meaning or original private
error type is recovered. Its result must not be invalidated by the later
last-error drop.

The complete3d8af0 caller copies the first24 input bytes to a local owned
request and stores option byte0 at+0x18. It passes description
shell::wait_retry and three words at7a990: exact1,3,10seconds.
After retry returns, the result is saved inR14. A nonzero command
capacity calls714530 with its data pointer/capacity and raw third
argument0; zero capacity skips that deallocation. This is an ownership
release boundary, not an assertion that every empty command has zero
capacity or that a generic Rust destructor has the same layout.

The optional second value is inspected only after command ownership ends.
neg+jo at3d8b54..3d8b57 selects absence exactly for rawINT64_MIN.
On presence, pointer/length are supplied to3a13e0 at3d8b67 with an
output buffer reusing the now-dead command local. Native tag1 at local0
loads its error handle from+8 and destroys it at3d8b7b. Any other tag
skips that drop; meaningful source correspondence restricts the supplied
cleanup result to its admitted ordinary variants. The optional data
allocation is then released when its capacity is nonzero. The original
retry result remains inR14 and is returned at3d8b90. Cleanup failure
does not replace it on these ordinary paths.

4148b0's retained context is narrower semantically: it formats the prior
GPG request, invokes42a290 at414e75 with the separate but byte-identical
[1,3,10] table7c108, releases the command allocation and selects its
existing raw-zero/nonzero continuation. It is not a complete proof of
download, GPG, keyring or publication behavior.

## 6. Escaped frames and exceptional boundaries

Let T denote each body's own entryRSP. Valid aligned stack storage must
cover its local frame, saved registers and return address; ordinary call
and return pushes/reads are included. Nested opaque callee stack footprints
are external premises, not bounded by these local intervals.

| Body | Body base | Escaped local regions and requirement |
|---|---|---|
|42a290|B=T-184|B+0x30..+0x40 is the in-place sleep structure; B+0x0c..+0x10 stores raw code; formatter later borrows B+0x30..+0x60, B+0x60..+0x70, B+0x18..+0x28 and B..B+8; output B+0x70..+0x88 is writable and nonaliasing.|
|3d8af0|B=T-72|B..B+0x19 holds the copied request including option0; only after retry and command release may cleanup reuse B..B+0x10 as its result. Original optional-value words at input+0x18..+0x30 remain readable/preserved.|
|3f5ca0|B=T-120|675690 may initialize B+0x30..B+0x60; the copy at B..B+0x30 is then borrowed by3f5f40. Original24-byte string words and their owned payload survive until transferred.|
|3f5f40|B=T-88|B..B+0x50 holds the complete record across allocation; fresh output80 bytes do not overlap live frame/input/last-error storage in a way that invalidates the transfer.|

Saved-register regions are above each local frame; the return address is
[T,T+8). Original input slices must not alias writable callee-local output
regions. The attempt may perform its own modeled effects but must preserve
all data needed later; destruction must preserve the new/final result.
The context wrapper's movaps uses the actual16-byte stack alignment obtained
from the admitted entry alignment and prologue.

All raw FDE/CIE and call-site coordinates are retained, including landings
42a492,42a49b,42a4a9 and caller/constructor cleanup tails. The ordinary
proof starts at each real entry and follows only normally returning calls;
it neither uses exception landings as an initial state nor claims their
destructor order/rollback. Allocation fatal paths and UD2 are explicit
nonordinary boundaries. Invalid current-error pointers, faulty destructors,
exceptions, aborts and nonreturning callbacks are excluded, not silently
treated as success or as a returned typed error.

## 7. What the future source qualification must establish

The safe API must preserve all ordinary attempt/sleep/error/final-builder/
owned-cleanup events and returned terminal identity while using the unchanged
duration dependency. Callback responses must be created only when requested,
so unused scripted errors or final results are not eagerly constructed and
dropped. The observer's trace ends at the operation return boundary while the
returned terminal value remains owned by its caller; later caller destruction
is not an internal protocol event.

An independent frozen oracle must use the total-nanosecond recurrence above
and supplied finite response histories. Required witnesses include initial
success, null/default versus supplied empty, zero-converted delays, every
success position/exhaustion, retained full schedule, identity/drop order,
INT64_MAX splitting, zero/progress/no-progress interruptions, ignored code0
remainder fields, optional cleanup absence/empty/error and result preservation.
New safe refusals need separate domain labels and a contract fixed before
source authorship. A compiling mutant is evidence only after producing a
complete input-only value stream; failure to compile or a partial stream is
not a semantic kill.

The phase freeze binds this argument together with its dependencies, event
corpus and static corruption controls. Independent peer/root admission and
all later source/build qualification are separately recorded; none follows
merely from this written proof.
