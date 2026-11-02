# Visor one-value result relation: manual integration proof

Target: Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`; repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. This is a conditional static normal-result argument. Reproduction and negative-control results are recorded separately in VALIDATION.json; the argument does not establish target runtime equivalence, a Rust port, a full configuration parser, an original ABI or a full-scope gate.

## Exact scope and premises

The question is the tag/code relation of the complete value visitor `4a7cf0..4a8c44`, after its four-byte whitespace scan, on stable valid UTF-8 input/state/output/scratch storage with no aliases or concurrent modification. State+18/+20/+28 provide the input pointer/length/cursor; cursor is in0..length with length<2^63. Original source-language layouts are not presumed beyond those observed offsets. Calls must preserve the admitted frames and return the bound result layouts. Normal allocation/copy/formatting/position-helper behavior is a premise; invalid storage, allocation failure, unwind, diagnostic text and runtime dispatch implementation are outside this relation. Every numeric value remains opaque: only error-tag/pointer propagation is used.

Recursion admission means state+48 is nonzero, or it is zero and state+49 is at least2 before entering the object arm. The quote arm does not touch the depth counter. With enabled checking, zero counter reaches a diagnostic/UD2 corridor; one is decremented to0 and selects error code24. These cases are separate from admitted object success. For admitted counters2..255, the shared decrement/restore cannot overflow if callees preserve those depth fields.

The conditional language is a quoted exact recognized name, or a single-member object whose decoded key is an exact recognized name and whose value is the literal null. Four whitespace bytes9/10/13/32 are permitted at the native scans. The selected name gives tag0 and its code0..78; normal error paths give tag1. A successful string/object consumes one value, so this relation does not demand exhaustion of trailing input. The outer configuration wrapper's suffix checks and fallbacks are separate1516 evidence. There is no sequence/array form or implicit default in this visitor.

## Quote arm and name relation

At `4a7d66..4a7d7b`, a quote calls `4ab660` without preconsuming it. That helper scans the same whitespace, consumes the quote, clears the scratch length, calls slot7e6050->`64f440`, and distinguishes native string tag2 from tags0/1. Tag2 is wrapped as sentinel4f plus payload. Other tags pass the decoded byte pointer/length to `4a8d80`. Name-result tag1 likewise becomes sentinel4f through the diagnostic wrapper; tag0 carries its code and original state pointer.

The addressed proof in `NAME-PROOF.md` covers the separate result-name leaf: exactly79 names/codes, otherwise tag1 on a normal diagnostic return;134 literal fragments,123 fixed constant operands,12 dispatch entries and bounded direct reads. It explicitly handles the code22 edge-role inversion and all shared literal liveness. The earlier raw-AL leaf1550 is only an independently frozen expectation source, not a substitute for this new proof.

The parent sentinel check at `4a7d78` sends4f to tag1. Under the result-name relation, every other returned byte is0..78, so it safely selects the79-entry table at87a78. Every table destination writes the identical code at output+1 and joins `4a8bad`, which clears the result tag. The static audit binds all79 destinations/stores; no code-range claim is taken from an unchecked index.

## Unit-object arm

`4a7d8f..4a7dc8` admits only `{`, performs the selected depth check/decrement, advances the cursor past `{`, saves the state pointer and calls `4ab3a0`. That helper scans whitespace, requires a quote, decodes the key with the same string/result-name helpers, then requires and consumes a colon after its whitespace scan. An empty object, unknown key or malformed key/colon returns sentinel4f and a diagnostic payload. A successful result has code0..78 plus the original state pointer.

At `4a7e13`, the parent calls `4ab530` on that state. The manual unit corridor in `UNIT-NOTES.md` establishes whitespace followed by the exact n,u,l,l bytes, checked against separate bounds, cursor advanced by4 and RAX=0 at `4ab5fc`. The helper itself accepts that prefix without checking a delimiter. All other normal paths return a nonzero diagnostic pointer as established below. Thus zero is a real unit-success discriminator, rather than an assumed enum tag.

The second79-entry table at87bb4 dispatches the preserved code. Every entry tests the unit result qword: nonzero reaches `4a8b20` with error selector BPL=1; zero retains the corresponding code, clears EBP and proceeds. Code44 uses the late/inverted block `4a8bc3`; code1 reorders the explicit R12B cleanup flag assignment. Both exact exceptions are audited rather than generalized away.

Shared bookkeeping at `4a8b23..4a8b38` restores the enabled depth byte before either the error return or closing-brace validation. For an error selector, the preserved diagnostic pointer is stored and tag1 is written. For a zero selector, `4a8b49..4a8baa` skips only9/10/13/32, requires `}`, advances past it, stores the selected code and reaches tag0. Hence null followed by a comma, another member, wrong closer or exhaustion cannot succeed on this arm. Disabled-depth state skips both changes; admitted enabled-depth state has net zero depth change on these normal corridors. Cleanup/unwind flags are retained as context, with no unwinding equivalence claim.

## String, escapes and Unicode

`STRING-PROOF.md` supplies the scanner and decode argument. The first-special word mask is justified by a byte-carry induction, not an assertion that later flags are exact. TZCNT is reached only for a nonzero mask; scalar tail and complete-word read bounds preserve the first-special/end cursor. Eight simple escapes, u dispatch, all512 signed hex lookup entries and the complete four-hex guard are independently bound. Malformed/short hex may consume bytes before failing; no rollback claim is made.

The surrogate guards partition all65536 units into high/low/non-surrogate classes. A valid pair gives `10000 + ((high-d800)<<10) + low-dc00`, and the retained SIMD literals encode the four-byte result. Pure arithmetic checks compare all1,112,064 scalar values and all1,048,576 high/low pairs to an independent Unicode codec, supporting the addressed byte-expression proof. They do not execute target code or establish buffer/call safety. Frame/capacity/copy preservation remains explicit.

## Nonzero diagnostic origin, including invalid unit types

The root diagnostic allocation at `64dfe0..64e059` has one ordinary return at64e02d. Its allocation result is tested at64e00a, zero goes through the failure call and UD2, and the normal return retains the tested nonzero pointer. `4aa4c0`, `4ab200`, `64cb40`, and `64d430` compute position context and tail-jump through slot7e5680 to this root. Position values and runtime-selected newline helpers do not determine pointer nonzeroness, provided their frames conform and they return normally.

`64ef10` writes string-error tag2 and that payload; `64ef70` writes byte-error tag1; `64f070` writes word-error tag1; `64efc0` returns the pointer directly. Hex and Unicode error paths use these wrappers. Their normal error payloads therefore remain nonzero.

The formatted-name/type route `4ac5b0` -> `4ad1b0` and type adapters7e5790->`64e370`,7e6080->`64cad0` -> `64e430` all end at slot7e65e0->`64d740`. The latter has one ordinary return at64db4a; its final40-byte allocation is tested at64db16 and zero goes to64de4f then the diagnostic/UD2 corridor. No intervening normal-path instruction changes the nonzero allocation result before the return. Formatting, message parsing/truncation and diagnostic contents remain opaque; that does not weaken the pointer discriminator. `4ac640` either retains its admitted nonzero incoming pointer or replaces it with a newly constructed nonzero one before returning.

For non-null unit tokens, `4aaef0` always constructs an invalid-type diagnostic or propagates a parser diagnostic. Literal false/true/null, strings and container token categories use the bound nonzero formatted path; numeric categories parse a number only to form a type error. The relevant pointer contract is closed without claiming any numeric value or floating-point equivalence:

- `4aa880` tag3 payloads come from4aa4c0/4ab200, propagated error variants of7e6070->64ce40, or the tail-called4aa530 result. Non-error numeric records take the invalid-type formatter path in4aaef0.
- `4aa530` tag3 is written only from a nonzero error payload in its temporary record; its producers are4aa4c0/4ab200,4aac60 and7e6068->64d220. The alternative numeric bits are opaque.
- `4aac60` and `64cbb0` have normal error variants populated by4ab200 and64d430 respectively. Their special tail transfer through7e6078->64d380 is included; a call-only inventory would miss it.
- `64ce40` error variants arise from64cb40/64d430 or propagate the error variant of64cbb0/64d220. `64d220` propagates64cbb0 or constructs its error via64d430. Its arithmetic success path writes tag0.
- `64d380` either writes success tag0, or calls64d430 and writes tag1 with its nonzero payload. This closes the tail edge's error-origin contract. Decimal/exponent predicates and computed float bits are not reconstructed by this pointer argument.

Consequently `4ab530`'s non-null/malformed normal returns cannot accidentally equal its zero null-success value under the stated frame/call premises. No error-payload address, text, cost or stable allocation identity is promised.

## Independent expectations and reproducibility

The39,177-case corpus was frozen before the independent abstract JSON model.
It covers quoted/escaped names, unit objects, invalid unit values, unknown names
and malformed/extra-member boundaries. The model agrees and rejects eight
deliberate rule simplifications. Its fixed domain has depth checking disabled
and asserts only tag/code, not cursor values or complete-input exhaustion.
It is neither observed target output nor a proposed native port.

VALIDATION.json records39 complete FDEs /19,057 bytes /4932 raw instruction
rows, GNU2.42/LLVM18.1.3 partition agreement without masks, independently
regenerated records, normal/optimized identical receipts,13 integrity controls
and1383 isolated below-image-identity binding controls in each mode. The
arithmetic checks cover65536 surrogate guards,1112064 scalar encodings,
1048576 surrogate pairs,256 scanner byte-lemma inputs and73728 word scenarios.
These support the addressed argument; they do not turn its explicit frame,
allocation/copy/format/position contracts into whole-ELF or runtime proofs.

All authorized root doctor/verify/catalogue-check/reproduce checks passed.
Full make test and hosted CI were not run; no Rust/compiler or full-scope gate
is claimed. Original failed annotations and working drafts are preserved in
operator evidence; HISTORY.md states the exact corrections and provenance.
