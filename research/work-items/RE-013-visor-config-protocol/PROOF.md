# Visor configuration-byte requests, fallback acquisition and trim

This addressed manual proof is conditional static research. It does not claim a full configuration parser, recovered Rust component or executed target comparison. Target:
Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes; base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Only immutable-image reads, ELF parsing and native disassembly were performed.

## Bounded question and premises

Which byte can reach global factory output `+0x48`, and why is a missing
recognized field different from an outer file/parser error? Parser grammar and the large value-conversion language remain explicitly outside this claim.

Assume valid, stable, nonaliasing and nonwrapping input/output/frame storage,
the selected byte slices are valid UTF-8 when a decoding helper requires it,
the loaded call targets match the bound relocations, normal external returns
respect storage/register contracts, and cleanup does not unwind or mutate
retained state. No actual HOME, selected directory, file content, loader state,
filesystem outcome, concurrent stability, allocation ABI or original Rust type
is inferred. The file-result convention, formatter/writer behavior and cleanup contracts are premises, not new ABI or operating-system proofs. Imported calls must return normally with the stated valid storage; diagnostic paths are described only up to the bound call and ensuing UD2.

## Global factory and primary request

The already credited initializer `0x4acbd0` acquires an H tuple, calls its
directory selector to obtain G1, and checks the selected directory before
continuing. The descriptor at `0x6486e` is exactly `c0 05 /code 00`.
Its owned-string callback `0x4ac590` is credited prior context. The formatted
bytes are G1 concatenated with `/code`, with no new normalization claim.
The reader at `0x4ac9c0` receives this formatted pointer/length at `0x4acc78`.
Its returned AL is stored at factory output `+0x48` at `0x4accae`.

Reader `0x4ac9c0..0x4acb6d` formats its supplied bytes followed by
`/static_config`: descriptor `0x65828` is `c0 0e /static_config 00`;
callback `0x4acb70..0x4acb83` loads its object's pointer/length at offsets
0/8 and tail-jumps to the credited string writer via `0x7e4c50`.
The primary read helper is requested at `0x4aca1c`, slot
`0x7e5f38 -> 0x68e5b0`. This does not establish OS paths or file contents.

The exact first-qword marker `0x8000000000000000` is tested by NEG overflow
at `0x4aca2c..0x4aca32`. Its path cleans the retained read error at
`0x4aca37`, selects byte `0x21` at `0x4aca3c`, then performs normal cleanup
and returns. Other first-qword values initialize the parser state and call
`0x4aa3b0` at `0x4aca8e`. If that call returns tag zero, the reader preserves
the byte at result+1; every nonzero returned tag selects `0x21` at
`0x4acb05..0x4acb11`, subject to cleanup returning normally.
Tag one has additional retained-error cleanup before this choice.
The selected byte `0x21` is not assigned a semantic name or reserved-value interpretation here; the complete value map is outside this claim.

## Parser wrapper and field-dependent fallback

Wrapper `0x4aa3b0..0x4aa4be` initializes a state, invokes `0x4ab790`, and
only for its returned success tag checks the unread suffix. Remaining bytes
9, 10, 13 and 32 are skipped using mask `0x100002600`; a different remaining
byte routes through error construction at `0x4aa47a..0x4aa498`.
This is an addressed suffix condition, not complete JSON grammar evidence.

The raw `0x4ab790..0x4ac58f` listing compares a decoded 8-byte key to
`aws_name`. The recognized field's initial marker is `0x4f` (at `0x4ab857`).
If a recognized key is reached with a marker other than 0x4f, control goes through an error path. This is not an unconditional duplicate-field theorem without proving the value visitor never returns 0x4f on success. The value visitor
`0x4a7cf0` is invoked at `0x4abf07`. The recognized parsed value is retained
from result+1. The selected object-close block with marker0x4f and selected empty-sequence block invoke slot
`0x7e6d50 -> 0x4a8c50`; this fallback is not a constant byte producer.
Do not infer arbitrary unknown-field handling, escaped-key grammar, full
nesting/error behavior or all visitor values from these selected anchors.

## Fallback has a separate acquisition and read

Default producer `0x4a8c50..0x4a8d7e` first calls
`0x7e6d38 -> 0x4a7c20`, then reads the returned pointer/length via the same
read-helper slot at `0x4a8c76`. Path producer `0x4a7c20..0x4a7ce9` calls
`0x7e6d40 -> 0x4ac8c0` and `0x7e6d48 -> 0x4ac6a0` again. These are the
credited H producer and selector, but fresh results H2/G2 must remain
distinct from factory H1/G1. No equality follows without additional stable
environment/metadata premises. Its descriptor `0x6654b` is
`c0 09 /aws_name 00`, and callback `0x4a7c00..0x4a7c14` loads pointer/length
from the owned tuple at offsets 8/16 before the same credited string writer.
Thus the second requested byte string is G2 concatenated with `/aws_name`.

The fallback reader marker uses the same exact NEG-overflow condition at
`0x4a8c96..0x4a8c9c`. That marker routes to a diagnostic call at `0x4a8d0a`
and then UD2 at `0x4a8d37` if it returns. On the non-marker route, bytes
are passed through `0x4ace20` and then conversion slot
`0x7e6d58 -> 0x4a9ae0`. Conversion AL `0x4f` routes to another diagnostic
call at `0x4a8d31` and the same UD2. Every other AL is retained across
normal cleanup and returned. Diagnostic literal `0x87f8f` is the 43 bytes
``called `Result::unwrap()` on an `Err` value`` (backticks are literal bytes).
Do not claim the diagnostic helper's complete behavior or unwind closure.

The outer reader's byte-0x21 fallback only acts on a returned file marker
or returned parser tag. It cannot be applied to this inner diagnostic/UD2
path without inventing an exception-to-result conversion. Actual failure
behavior still depends on the diagnostic helper's contract.

## Addressed trim proof

`0x4ace20..0x4ad0b7` scans code points from both ends. Under valid UTF-8 and
storage premises, its addressed predicates skip code points 9..13, 32,
0x85, 0xa0, 0x1680, 0x2000..0x200a, 0x2028, 0x2029, 0x202f, 0x205f and
0x3000. Slot `0x7e4cc8` binds table `0x87579`. Low-page paths load a table
byte and test bit 0 directly; page-0x20 paths shift right once before testing
bit 0. These are different table bits. Table indices 0..10, 40, 41, 47 and
95 describe page-0x20 entries, not low-page whitespace characters.
The leading loop keeps RCX as the bytes before the current decoded point and
RDX as the bytes through it. On its first non-whitespace point, RSI is the
end of that point, RCX is the leading-whitespace length, and RDX is the byte
offset through that first retained point. On leading exhaustion, instructions
`0x4acf70..0x4acf74` explicitly zero RCX and RDX before the common return.
Consequently nonempty all-whitespace input returns the original input pointer
with length zero. Empty input also returns the original pointer and zero.

The trailing loop leaves RSI at the end of the first retained point and moves
RDI backwards by whole valid UTF-8 code points. If it reaches RSI while
discarding trailing whitespace, RDX still identifies that first retained
point's end. Otherwise R9 holds the end of the last retained point and
`0x4ad0a8..0x4ad0ab` computes RDX = old_RDX - RSI + R9 = R9 - input_pointer.
The common return `0x4ad0ae..0x4ad0b6` subtracts leading bytes RCX from RDX
and adds RCX to the original pointer in RAX. It therefore returns the maximal
middle slice, keeping all interior code points. Each loop consumes at least
one byte per decoded point, so valid finite inputs terminate without calls.
This is an addressed manual proof, not a runtime comparator. Do not substitute host-language strip semantics or
claim behavior for malformed UTF-8 or invalid storage.

## Selected field-control qualification

Only addressed control predicates are claimed for `0x4ab790`, under its initialized parser-state and helper-result premises. The full FDE is retained to avoid pretending selected windows close all grammar.

At `0x4ab937..0x4ab94d`, a decoded length8 key equal to `aws_name` selects the recognized path. At `0x4abe98..0x4abe9d`, a local marker other than0x4f selects error construction at `0x4ac44a`. Otherwise the normal value visitor call at `0x4abf07` routes returned tag1 to the error path; its other conforming return (tag0) copies byte+1 into the local marker at `0x4abf17..0x4abf1c`. No complete visitor map is inferred.

On reaching object close at `0x4ac010`, marker0x4f calls the default producer at `0x4ac01b`; any other marker bypasses that call. On reaching the selected empty-sequence block at `0x4abffa..0x4ac001`, the same default producer is called before later closing/suffix validation. Both observations precede the wrapper's unread-suffix check. Thus eventual rejection of trailing input is not evidence that the fallback producer was never invoked. No arbitrary input acceptance, absent-field iff theorem, unknown-field skip closure or exception-to-result bridge is claimed.

## Validation and attribution

See README.md and VALIDATION.json for exact commands, repeated native exports, raw GNU/LLVM partitions, below-identity binding/data/relocation controls, abstract support and root-check outcomes. An instruction identity inventory is not a semantic-proof count. All original byte ranges are retained without normalization masks. The full selected parser extent and the factory ranges are contextual coverage, not newly recovered implementation bytes.

The formatter/writer request interpretation is credited context from merged RE-013 visor-format-requests (#1345). Factory/provenance context has also been qualified in draft #1402; this packet binds its immediate descriptor/callback/store context directly and treats H/G producers as opaque fresh tuple sources. No result depends on copying unlicensed reference code. All source and prose here is independently authored MIT work. All component gates remain unchanged.

Remaining gaps: actual environment/FS contents and side effects, synchronization, reader result ABI, allocator/destructor/panic/unwind internals, complete JSON/key/value grammar, conversion labels/map, malformed UTF-8 behavior and a target/runtime comparator. No captured execution, CPU instruction evaluation, live networking, Rust build, hosted CI, full-node equivalence or byte-recovery credit is claimed.
