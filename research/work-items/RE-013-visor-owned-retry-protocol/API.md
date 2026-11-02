# Chosen safe value API contract

This is a pre-source contract for a real src/visor-retry-protocol crate, with
one local path dependency on the unchanged visor-duration-value crate.
Names and Rust types are new. No original source signature, private layout,
allocator identity or host clock is inferred.

## Borrowed retry operation

The retry operation borrows an opaque request R, a description string and
an optional raw-u64 delay slice. It accepts three supplied callbacks:

- attempt borrows the same R and returns either success or a new owned E;
- sleep accepts a canonical request and returns a raw reply;
- terminal builder receives borrowed description, the complete selected
  raw delay slice and the last E, and returns an independent owned T.

The returned value is either Succeeded, Exhausted(T), or a named safe refusal.
Neither E nor T requires Copy or Clone. The terminal builder is called at
most once; its provided T is returned unchanged and remains alive through
the operation return. The request and description are borrowed, not copied
into a substitute provided value. The native attempt's fixed location and
the terminal formatter's fixed callback/token composition are curried into
the supplied callback correspondence, as stated in PROOF.

A sleep request has private canonical fields: seconds in0..=INT64_MAX and
nanoseconds in0..1e9. It exposes those numeric values and the fixed raw
clock1/flags0 values for a supplied adapter. It does not itself call an OS.
The raw reply contains a signed32 code and two signed64 remaining fields.
Code0 ignores both remaining fields, including negative or noncanonical
values. Code4 validates both fields against the current request before any
add-back. Other codes become UnexpectedSleepCode(code).

A code4 remainder is valid exactly when seconds>=0,0<=nanoseconds<1e9,
and its pair is lexicographically <= the current request. Otherwise return
InvalidRemainder. On either safe refusal the current attempt E is destroyed,
no new attempt or terminal builder is called, and the borrowed request remains
with its caller. These policies deliberately replace native nonordinary or
excluded callback behavior; they are never counted as native-return matches.

The generic API does not preconvert the full schedule. It performs the initial
attempt first, selects None/default versus Some(empty) after an initial error,
and converts only the next reached raw word. Every word is a valid raw input
to the unchanged converter, so there is no invented float-validation refusal.
Default words are exact preserved raw encodings, not decimal constants
re-parsed by a host floating implementation.

## Owned request with optional cleanup

A second operation consumes an opaque command C and optional cleanup value P.
It specializes the native owned caller: description shell::wait_retry,
option byte0 and the exact raw delay list[1,3,10]. Its supplied attempt
borrows the same owned command value and corresponds to the native copied
request with option0. The request's raw layout is not recreated.

It uses the same supplied sleep and terminal-builder callbacks. After an
ordinary Succeeded or Exhausted result, it explicitly ends C ownership.
For Some(P), it calls the supplied cleanup adapter on borrowed P. A cleanup
failure supplies an owned cleanup-error CE, which is destroyed before P.
Then P ownership ends and the original result is returned unchanged.
None skips both the adapter and any unused cleanup response. Empty command
or cleanup values do not imply absent values; their ownership and adapter
order remain defined. Actual deallocation capacity checks remain native
representation details governed by the ownership correspondence.

On either new safe refusal, it ends C ownership, then P ownership if present,
without calling cleanup, and returns the refusal. This is the declared new
policy, not native panic/unwind or filesystem behavior. All caller-supplied
destructors and callbacks must return normally for this value relation.

## Observer and supplied-function fixtures

The future input-only client will use independent tracked resources and weak
identity witnesses. Attempts and cleanup create owned error resources only
when the callbacks are actually called. The terminal resource is created only
inside the terminal callback, not eagerly captured by an unused closure.
Callbacks receive the same supplied resource identity; normal replacement
keeps the preceding E alive while the next attempt runs. The terminal builder
must observe the last E still alive, and the returned T must preserve its
provided identity through later owned cleanup.

The trace records callback invocation, reached response, resource creation,
destruction and the returned value at the operation return boundary.
Returned T stays owned by the caller while this trace is captured. Destruction
by that caller afterward is outside the operation. Ordinary resources borrowed
by the generic retry remain alive outside it. These measurement boundaries
are explicit and do not redact raw output from any later qualification run.

Finite input transcripts describe total supplied callback functions: attempts
use a finite explicit response prefix followed by success; sleepers use a
finite raw-response prefix followed by completion0 with zero fields. This
avoids pretending that a finite array exhausts a real native callback.
Unreached response suffixes are never semantically validated. Their transport
frame must still be well formed. Named cases and expected events are separate
from the opaque-ID input stream and are unavailable to the client.

Exact framing and output serialization will be frozen in PROTOCOL.md together
with the independent event oracle before any Rust/client authorship.
