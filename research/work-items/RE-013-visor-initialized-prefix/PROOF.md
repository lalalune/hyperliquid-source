# Addressed initialized-prefix argument

Task RE-013, component `visor`. Target: captured Visor, 8,305,392 bytes,
SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Addresses below are linked ELF virtual addresses. This is a manual static
normal-return argument, supported by retained full FDE/CIE records, decoded
instructions, actual RELA bindings and data records. It is not a CPU evaluator,
original Rust reconstruction, live environment query or concurrent execution proof.

## Premises and exact claim

Assume valid stable nonaliasing input/output/storage, the observed callback
records, normal ABI callee-saved preservation, ordinary imported copying, and
normally returning opaque helpers that preserve live data outside their declared
outputs. Successful allocation, formatter callback behavior and allocation growth
with prefix preservation remain premises, as in the prior formatter/path packets.
Error, panic, unwinding, lock contention/poisoning and concurrent mutation are not
proved. No promise is made that any abstract branch is feasible in a real run.

Let H be the byte slice returned by `0x4ac8c0`. The prefix selector constructs
A = H || `/cham`, then, if its first metadata test does not accept A, constructs
B = H || `/hl`. Let D1/D2 denote the corresponding observed acceptance predicates:
result tag != 2 and `(mode & 0xf000) == 0x4000`. Let Z be the later preparation
helper's observed RAX == 0. On the ordinary returning selector paths:

| D1 | D2 | Z | returned tuple |
| --- | --- | --- | --- |
| true | any | any | A |
| false | true | any | B |
| false | false | true | B |
| false | false | false | explicit error call then UD2, no ordinary return |

Error-drop helpers on tag-2 routes must themselves return for those rows.
The preparation request supplies word `0x1ff` and byte `1`; the detailed
filesystem contract of that helper is not recovered by this table.

If the factory completes its separate post-selection metadata check and the
observed initializer callback publishes its returned fields, G consumed by
the prepared-path caller is this selected A/B tuple at global +0x18. Consequently
the prior packet's P = G || `/tmp/` || X uses one of these byte constructions
under the combined premises. This does not reveal the actual H/G/X, guarantee
a filesystem operation, normalize slashes, or establish shell execution.

## Caller, descriptor and publication chain

`0x3a17bf` loads slot `0x7e53e8`, whose unique RELATIVE relocation points to
global object `0x7e9e58`. `0x3a17c6..0x3a17cc` tests the +0x50 word; the
nonzero path supplies its address in RDI, ESI=1, an indirection containing the
global pointer in RDX, and descriptor `0x7ae488` in RCX to slot `0x7e53a0`.
That slot resolves to `0x6723e0..0x6725fc`.

The adapter saves descriptor RCX at `[rbp-0x50]` and argument RDX at -0x48.
On its callback arm, `0x6724cc..0x6724d4` reloads them and calls descriptor
+0x20, not +0x18. Actual slot `0x7ae4a8` resolves to `0x39d910`.
The adjacent +0x18 relocation resolves to `0x3a7eb0`, a different callback;
it is retained as a negative selection binding, not counted as a selected FDE.
The adapter's atomic/LOCK/wait paths are retained, without a concurrency theorem.

`0x39d915..0x39d91b` follows the two caller indirections, saves the global
object in RBX and clears the indirection slot. Its nonnull/nonpoison callback
arm passes the local stack result buffer to `call [rbx]` at `0x39d930`.
Global first-word slot `0x7e9e58` has its own RELATIVE relocation to factory
`0x4acbd0`; its raw zero file word is not a zero loaded function pointer.
The factory call therefore follows this binding under the stated initialized
image/callback premises. After return the callback copies five 16-byte chunks
from local result to the global object; the chunk from local +0x10 copied to
global +0x10 contains bytes +0x18..+0x1f, and the +0x20 chunk contains the
remaining selected tuple words. This does not assert every copied padding
byte was initialized. Raw file state at global +0x50 is 3; it is not an
observation of the runtime state word or of successful publication.

After the adapter returns, `0x3a1abf` rejoins `0x3a17d2`, which adds 0x18 to
the retained global pointer. The callback `0x39a750` reads this tuple's +8/+16
words. The current caller does not re-prove global initialization or prevent
concurrent changes; those remain premises of the relation to G.

## H producer and its limits

Factory call slot `0x7e6d40` resolves to `0x4ac8c0..0x4ac9bd`.
It calls `0x7e6c28 -> 0x4a5890..0x4a5aa7`. That source writes the bytes
`HOME\0` at local +0x40, supplies pointer and length 5 to
`0x7e5e98 -> 0x498290`, and then passes its accepted pointer to the direct
callee `0x66c270`. For these five constant bytes, the validator's scalar
scan reaches the unique final zero at index 4; `0x498373..0x498386` publishes
tag zero and the original pointer/length. No broad C-string grammar is claimed.

`0x66c2ad` calls the actual GLOB_DAT symbol `getenv` at slot `0x7e7c20`.
On a nonnull result it calls imported `strlen`, allocates/copies positive
length bytes and returns a tuple, or returns an empty tuple for length zero.
A null result writes first word `0x8000000000000000`. Locks, contention,
interposition, environment lifetime and complete ownership are not proved.

The source compares its result against `0x8000000000000001` and
`0x8000000000000000`. Only the ordinary positive-length value arm returns
the environment-derived tuple directly. Missing/error/empty cases reach
fallback: imported `sysconf(0x46)`, capacity default 0x200 on a negative
answer, imported `getuid`, and imported `getpwuid_r`. It requires EAX==0
and a nonnull returned pointer before taking the local +0x60 word, applying
`strlen`, and copying bytes. The exact passwd structure/source ABI and error
recovery are separate obligations; no actual user/home data was queried.
On the sentinel error arm only the first output word is written.

The outer H adapter detects the minimum signed 64-bit sentinel with NEG/JNO
and returns the empty tuple on that arm. Other source results are passed to
`0x7e4d28 -> 0x49b560`; tag 1 selects the empty result. On the other arm it
copies the returned pointer/length through an internal allocator and imported
memcpy. It returns the new pointer/length, including an ordinary zero-length
case. The detailed conversion acceptance language is not recovered here;
H must not simply be identified with the raw HOME value on all paths.

## Selector byte requests and ordinary-return branches

At `0x4ac6b4..0x4ac6ce` the incoming slice is retained at local +0x18/+0x20;
the argument record points there and uses callback `0x4acb70..0x4acb83`.
That callback reads the slice at +0/+8 and tail-jumps through
`0x7e4c50 -> 0x499ae0`. It differs from the owned-tuple callback
`0x4ac590..0x4ac5a4`, which reads +8/+0x10.

The first format stream `0x6a568` is exactly `c0 05 /cham 00`; the second
at `0x64868` is `c0 03 /hl 00`. Each substitutes argument zero before the
literal suffix, through the reused, full-FDE formatter context. No path
join or trailing-slash normalization is performed by these data requests.

`0x4ac708` tests the first metadata result tag. Tag 2 calls the error-drop
helper and proceeds to fallback; otherwise `0x4ac71b..0x4ac729` performs
the mode mask/test. Acceptance writes the first saved capacity/pointer/length
from RBX/R14/R12 to output at `0x4ac72b..0x4ac732` and returns.

Fallback formats B at `0x4ac744..0x4ac753`, saves the complete tuple at
local +0/+8/+0x10 and uses its pointer/length for the second metadata call.
The tag/mode tests at `0x4ac782..0x4ac7a3` either accept B, or pass B with
the `0x1ff`/1 request to `0x7e5f50 -> 0x679ba0`. RAX zero reaches the same
copy-out at `0x4ac7c8..0x4ac7d5`. Nonzero reaches `0x4ac801..0x4ac80c`,
an error call followed by UD2. No ordinary RET selects A after this path.

The metadata adapter `0x686d10..0x686f28` retains its length/NUL handling
and full FDE. It calls direct `0x689980`; one returned-tag branch instead
reaches imported `stat64` via `0x7e7ed8`. Do not label every metadata call
as one unconditional stat64 request or infer all helper/OS behavior from
the import name. Our D1/D2 predicates are the caller's returned fields.

## Factory field identity and second check

Factory `0x4acbe8` obtains H at local +0x18; `0x4acc01` passes its
pointer/length to the selector, with output at local +0. It then makes a
separate metadata request for the selected tuple and repeats the tag/mode
gate at `0x4acc1c..0x4acc35`. A selector success does not itself establish
that this later check will accept. Failure reaches the literal error
stream `19 "cham_dir does not exist: " c0 00`, then an error call/UD2.
Unrelated bytes after its terminator are not part of the error format.

On the accepted path, the owned tuple is formatted using `c0 05 /code 00`
at `0x6486e`. A later reader is called with that third tuple, returns AL,
and must preserve the earlier local tuples. `0x4acc90..0x4acc9e` copies the
selector's complete local tuple to factory output +0x18..+0x2f.
The H tuple goes at +0; the G/code tuple at +0x30; AL at +0x48. This is
addressed byte-field provenance, not recovered original Rust field names,
full layout/padding or the meaning of AL. Reader context includes its
separate `/static_config` format; file contents/parsing/default AWS names
and its other effects are not qualified by this packet.

## Decoder qualification, controls and remaining work

Twenty complete FDE extents total 7,011 bytes. Eighteen have equal raw
GNU/LLVM partitions. Two contain seven LLVM18 standalone `f0` LOCK display
rows; all original bytes and outputs remain retained. Joining only the
seven explicitly addressed adjacent display rows produces the GNU partition.
No operand/byte mask is applied; this is not a claim of raw partition equality
on those two extents or a proof of atomicity. The original strict comparator's
failure is retained in VALIDATION, not represented as a successful first run.

The argument checker binds 91 instruction anchors, all selected data and
31 relocation slots. Three byte fixtures cover empty/trailing-slash inputs;
eight Boolean rows and three counterexamples guard the abstract selection.
Twelve below-image-identity mutations include both actual RELA addends,
descriptor +0x20 selection, output +0x18 copy, mode/preparation branches,
HOME key, getenv call and both suffix streams. These controls support the
manual argument and do not substitute for target execution or helper closure.

Further work: establish the complete conversion/metadata/preparation and
allocation contracts, error/cleanup/concurrency paths, source-built Rust with
documented dependencies, and an explicitly authorized isolated dynamic harness.
No component gate, function-recovery count or matched-window credit is requested.
