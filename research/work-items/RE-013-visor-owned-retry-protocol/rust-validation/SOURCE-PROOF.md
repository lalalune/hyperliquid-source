# Source correspondence for the owned retry protocol

This phase implements the immutable pre-code API, not an original Rust signature or layout. The native argument is conditional on the valid-memory, frame, independent ownership, normal-callback/destructor and termination premises in the original PROOF.md. Both phases bind only Visor SHA25689338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31. The complete core remains four FDEs/1,095 bytes/291 rows; six additional bodies are retained context/dependency evidence. No byte credit or component gate is added by authoring source.

## Actual graph and arithmetic dependency

The new five-file `src/visor-retry-protocol` package has one explicit path dependency, `../visor-duration-value`. The latter's five files, native proof, historical freezes and 336 public-manifest entries remain unchanged. Cargo generated the new two-package lock offline; metadata admits one root workspace member and two actual local packages, each with its real library and `value_contract` integration-test target. There is no root workspace, registry package, build script, proc macro, stub or copied conversion implementation.

`wait` calls the existing `convert_bits` only when the next selected word is reached. Its result has private canonical fields S in0..=u64_MAX and N in0..1e9. The dependency's integer-only source and prior all-binary64 proof supply that value relation; this phase does not rederive it from host floating point. NaN, signs, subnormals, rounding, the 2^64 discontinuity and large overflow boundary remain the unchanged dependency's contract. All raw words are valid converter inputs, and no eager float validation is introduced.

For each loop entry let U=S*1e9+N in unbounded mathematical integers. Source uses a pair and chunk q=min(S,INT64_MAX), unlike the pre-code oracle's total-nanosecond recurrence. Source subtraction R=S-q cannot underflow. The supplied request is(q,N), with private fields and fixed raw clock1/flags0; it cannot express invalid nanoseconds or seconds beyond the signed request bound.

Code0 sets the remaining pair to(R,0), so U decreases by q*1e9+N. It does not read either returned remainder field. If R=0, the loop ends; otherwise the next request has zero nanoseconds. There is no runtime sleep or clock call.

Code4 first rejects negative seconds, nanoseconds outside0..1e9 and a remainder pair larger than(q,N). These checks precede every signed-to-unsigned remainder conversion used for state. Short-circuit evaluation makes negative seconds unable to reach the unsigned comparison or add-back. On an admitted reply, 0<=r<=q, so R+r<=R+q=S<=u64_MAX. Addition therefore cannot overflow. N becomes the admitted remainder nanoseconds. The new total is U-(q*1e9+N_old)+(r*1e9+n), exactly the frozen oracle recurrence. Equality is allowed: finite termination requires finitely many interruptions, as in the native theorem. No arbitrary interrupt cap is added.

Other raw codes become `UnexpectedSleepCode(code)`; invalid code4 remainders become `InvalidRemainder`. These are new safe policies for native fatal/excluded paths. They are not recovered unwind behavior. The 48 policy cases remain separate from 727 native-conditional cases in every comparison.

## Borrowed retry and distinct error ownership

`retry` invokes the supplied attempt before selecting the schedule. Initial success returns directly without calling the sleeper or terminal builder. After error E, `None` selects the exact three default raw words; `Some(&[])` stays empty. The selected borrow preserves the full original bit sequence, length and order.

Every reached delay is converted and consumed before the next attempt. Zero duration skips only sleep, not the following attempt. On a sleep refusal, current E is explicitly dropped and neither attempt nor terminal builder runs again.

The next attempt is evaluated while current E remains in scope. If it supplies a successor, source drops the previous E and then assigns the new E. If it supplies success, source drops the old E before returning. Duplicate error labels do not conflate separately allocated values. E requires neither Copy nor Clone.

At exhaustion the FnOnce terminal builder receives the original description, entire selected slice and a borrow of the last E. Its T is obtained before E is dropped, then moved unchanged into `Exhausted(T)`. This is the safe typed projection of the native ordinary nonzero terminal result, whose allocator/null/record-initialization argument is already closed in the native proof. It does not recreate the opaque formatting/error ABI. T is separate from E and is not copied or reconstructed from a label.

## Owned command, optional cleanup and returned terminal

`retry_owned` borrows its consumed C for the retry operation and curries raw option0 into every attempt. It selects description `shell::wait_retry` and exact raw[1,3,10] seconds. Once retry returns, C is explicitly dropped. On ordinary success/exhaustion, `Some(P)` invokes the supplied cleanup adapter on the same P; an Err(CE) is dropped before P. None skips cleanup. An empty P is still Some and still invokes the callback.

The original retry result is held across these actions. T, when present, survives C disposal and the cleanup callback/error/value sequence; source returns the same T. On either new refusal, C is dropped, then optional P is dropped without calling cleanup, and the refusal is preserved. Rust scope cleanup also disposes callback closure values; the value theorem assumes those closure environments do not own overlapping E/CE/T/C/P and have no additional measured side effects. Arbitrary captured resource effects, panic or nonreturn are outside the ordinary supplied-callback correspondence.

## Input-only observations and their limits

The independently frozen frame supplies only opaque IDs, raw input bytes, labels and finite response prefixes. The client parses the complete batch before constructing any observed resource. It has no expected-file, provenance-label or case-name access. Unused suffixes must be structurally valid transport but are not semantically checked or materialized as error resources. Attempts default to success and sleepers default to code0 after their prefixes, exactly as frozen.

Actual C/P are Rc allocations with Weak witnesses. Each actual E has an independent creation serial and allocation, even for duplicate labels. T is allocated only by the called terminal builder; CE is created only by a reached cleanup failure. No unused E/CE/T is eagerly allocated by closure construction. Destructors append actual events. Weak strong-count and pointer checks observe the preceding error while the next attempt runs, last E during the builder, P/C callback identity, T during cleanup and the exact returned T allocation. No strong witness artificially extends their lifetime. The result is kept alive until the complete trace and return value are serialized; caller-owned T destruction after that boundary is outside the operation, not filtered from an existing trace.

The fixed frozen output does not contain the owned attempt option byte. The client adapter intentionally ignores that argument, so agreement of all 775 full traces alone cannot qualify option0. The dedicated `owned_option_zero_is_passed_on_every_reached_attempt` test checks every reached option and exact call count for failure prefixes0..4: initial success, each earlier success, and four-attempt exhaustion. Another ownership test checks option0 on all four exhaustion attempts. A separately classified option1 control must compile, produce the same full corpus streams and fail only the dedicated focused assertion in both profiles. It is not counted as a full-stream mutant kill.

The 11 focused tests check API/ownership regressions; they do not substitute for the prior native proof. The 24 proposed source mutations cover21 native-conditional changes and3 new-policy changes. A full-stream mutant only counts after successful real compilation and a complete775-row output; policy mutations must leave all727 native-domain outputs equal. There is no claim that all ownership violations or all callback implementations are exhaustively tested.

## Execution and qualification boundary

At this source freeze, only formatting, version, offline lock and metadata preparation have run. No Rust library, test, client or mutant has been compiled or executed. Later qualification requires a separate source/build gate, exact source/toolchain/ancestor/config admission and fresh output directories. Captured code remains non-executable static evidence. Neither an actual OS sleeper, command runner, cleanup effect, filesystem/GPG behavior nor whole-Visor equivalence is implemented or validated here.
