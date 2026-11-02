# Conditional owned retry contract

This additive pre-code phase extends PR1599. It reuses the exact existing duration value converter and preserves that contribution's source and historical evidence. The proposed operation is the complete owned retry/sleep/optional-cleanup protocol, under explicit supplied-callback and valid-memory premises. The phase freeze does not itself authorize source, client or build work.

The target is only Visor SHA25689338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31. Four complete core FDEs are42a290..42a4c2,3d8af0..3d8bf0,3f5ca0..3f5d0e and3f5f40..3f5fe7,1,095 bytes/291 instructions in the initial GNU export. The prior conversion dependency is330360..330581 plus7a6530..7a65a1. The shell runner, GPG caller and diagnostic callbacks are context; complete exports do not make them complete semantic theorems.

## Supplied values and normal-return relation

An attempt receives the same borrowed request object on every invocation. Native raw zero is the success variant of this protocol; it is not a proven external shell success. Every nonzero result supplies a fresh, uniquely owned current error with valid destructor semantics. The attempt, sleep, terminal-builder, cleanup and destructor callbacks must return normally, preserve all stated borrowed objects and stack frames, and not produce overlapping owned values. Their real command, filesystem, allocation, clock and cryptographic effects remain outside the relation.

1. Invoke the attempt before inspecting any delay element. Zero returns success immediately.
2. After an initial error, select the original delay list. Null selects exact raw words3f50624dd2f1a9fc,3fa999999999999a,3ff0000000000000. A supplied empty list is distinct and immediately exhausts. A supplied nonempty list retains its original order, bits and full original length.
3. For each reached word, apply the already qualified all-input duration conversion. A zero pair skips sleeping and immediately allows the next attempt.
4. For a nonzero pair(S,N), letq=min(S,INT64_MAX), request(q,N), and retainS-q unrequested seconds. Native raw clock/flags are1/0 and request/remainder addresses are identical. These raw arguments and the in-place external ABI are premises of the original call, not a host-OS action by the future source.
5. A sleep return code0 consumes the requested pair and ignores every returned remainder field. The next request, if there are unrequested seconds, has nanoseconds0. Return4 supplies a canonical nonnegative remainder no greater than the requested pair; replace the requested portion by that remainder, preserving unrequested seconds. Repeat until no time remains, then attempt again. Finite termination additionally requires finitely many interruptions and normally returning callbacks.
6. A new nonzero attempt result is obtained before the previous error is destroyed. Destroy the previous error exactly once, install the new error, then advance the schedule. On zero, destroy the current error before returning success.
7. On exhaustion, the terminal builder borrows the original description, complete selected raw-bit list and last error. It returns a fresh independent owned terminal value, after which the last error is destroyed. Return the terminal value unchanged. Exact rendered float/error diagnostic text is not part of this contract.
8. The ordinary owned caller runs the same operation with description bytes shell::wait_retry, option byte0 and explicit raw[1,3,10] seconds. It ends command ownership after retry returns. If the optional cleanup value is present, invoke cleanup with its borrowed bytes, destroy a supplied cleanup error if native tag1 is returned, then end cleanup-value ownership. Preserve the original retry result throughout. Absent optional cleanup skips the cleanup callback, including all unused scripted responses.

The native terminal constructor's ordinary return is nonzero: it allocates80 bytes, explicitly rejects null through a nonreturn boundary, and writes the complete record before returning. The48-byte context and24-byte formatted string ownership are opaque valid-initialization premises. This closes the nonzero final-error classification without inventing rendered text or backtrace behavior.

The actual two confirmed direct callers both select[1,3,10], never the default list. Their success/error branches and ownership projection are selected caller evidence. The full GPG/update caller, indirect caller population, signature authenticity, process execution and whole Visor lifecycle remain unqualified.

## Invalid and nonordinary inputs

The supplied source API is newly chosen safe Rust. Native correspondence is limited to valid nonwrapping input slices and original frames, canonical converter outputs, uniquely owned error objects, normal helpers and the bounded canonical interruption domain. No claim is made for invalid target memory, overlapping ownership, arbitrary original private tags, allocator failure, signals, panic, unwind or nonreturn.

Sleep codes other than0/4 reach a fatal helper andUD2 in the native body. A future safe API may report a separately named refusal instead; that is new policy, not an ordinary native result. Likewise, a reached code4 with negative, noncanonical or larger-than-requested remainder may be safely refused, with no claimed native invalid-input behavior. Code0 must ignore even invalid unused remainder fields. Extra unused attempt/sleep/cleanup responses and unused delay elements must not be semantically validated before they are reached.

The chosen safe policy is specified in API.md. A reached unexpected sleep code returns UnexpectedSleepCode with that raw signed32 value. A reached code4 with an invalid remainder returns InvalidRemainder. Either destroys the current attempt error without calling the terminal builder. The owned wrapper then ends command ownership and optional cleanup-value ownership in that order, skips the cleanup callback, and returns the refusal. These are new policies for native nonordinary/out-of-domain paths, not native unwind claims. No unsafe code, host sleep, shell, file operation, network or target-code execution will be included.

## Arithmetic and frame obligations

For admitted remainingS,0<=q<=S and q<=INT64_MAX. Subtraction cannot underflow. A valid interruption has0<=r_sec<=q, so(S-q)+r_sec<=S<=u64_MAX; add-back cannot overflow. Nanoseconds remain in0..1e9. A proof in total integer nanoseconds will establish the same sequence independently from the source's pair/chunk implementation.

For entryRSP=T, retry body base isT-184, owned-caller baseT-72, terminal-wrapper baseT-120, terminal-constructor baseT-88. Each body requires its actual stack alignment, valid saved registers/return address, and disjoint writable locals. Per-call escaped pointer regions and preserved memory are enumerated in PROOF.md. No fixed maximum for opaque callee stack use is inferred from these local frames.

The pre-code freeze binds this contract, native records, independent event corpus and actual controls. Independent root/peer review remains a separate admission. This document does not authorize source or compilation.
