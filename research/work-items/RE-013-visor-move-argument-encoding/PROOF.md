# Conditional move-request argument encoding

This is a manual argument over the SHA-bound native bodies in `observed/`, not an execution, instruction interpreter, source attribution, or claim about shell/filesystem effects. Function names below are local descriptions. `T = 0x8000000000000000`; triples mean the three observed words `(capacity-or-tag, pointer, byte-length)`, without assigning an original language type.

## Statement and necessary domain

At entry to `0x3a15d0`, let `(RDI,RSI)=(P,n)` and `(RDX,RCX)=(Q,m)` be two stable canonical UTF-8 byte slices. Define `W` as the 25 scalar values below, `blank(X)` as every scalar of X being in W (including empty X), and `E(X)` by the exact chunk grammar below. Under these premises:

1. Each read/write/pointer addition is in its valid object, does not wrap the address space, and has the required alignment. The two source slices may overlap each other, since they are only read. They do not overlap active frames, result objects, the iterator/record array, newly allocated buffers, relocation slots or mutable allocator metadata. All live slices, records, flags, result words and literals are stable except at the stated stores. Fresh allocations do not alias those live regions or one another. Assume `n+m <= 2^61-2`; this is a sufficient bound, not a necessity claim.
2. Execution uses the ordinary register/call behavior evident in the x86-64 instructions. Opaque callees preserve callee-saved registers and all live objects other than their expressly designated outputs. An output pointer escaping to a callee does **not** establish that preservation by itself. Imported `memcpy` has its ordinary non-overlapping copy contract. Its dynamic-symbol name and RELA are retained; host libc behavior is not measured.
3. The preflight call through `0x7e5608 -> 0x686d10` completes normally and supplies a valid result. A low DWORD equal to 2 supplies the valid error payload used by the error branch. Otherwise all `0xb0` copied bytes are readable and initialized. For the successful construction statement its low DWORD is not 2. No meaning such as existence, permissions or filesystem durability is assigned to this opaque result.
4. Every allocation/growth needed on the selected path succeeds normally with valid writable storage and capacity at least the requested initialized length, at most `T-1`, preserving the existing initialized prefix and its length. This applies to internal `0x70bf30`, `0x651670`, and `0x2be910`, not to presumed libc symbols. Returned storage is compatible with the observed cleanup `0x714530`; that cleanup returns normally and preserves the still-live output and other objects. The theorem does not show the allocator bodies satisfy these premises.
5. The selected ordinary calls return normally. Opaque error factories may return any word; no nonzero-error or success-if-and-only-if theorem is made. Unwinding, allocation failure, invalid/malformed UTF-8, unbounded/corrupt lengths, asynchronous mutation, unexpected returning diagnostic helpers and alternate entries into landing pads are excluded. Raw FDE/CIE retention establishes the chosen extents, not a proved unwinder or original compiler/ABI identity.

Then, conditional on the non-tag-2 preflight, the builder either reports an embedded NUL without calling `0x3d8d70`, or passes it exactly one object with option byte 1 and byte payload

`C = join_with_one_ASCII_space([b"mv"] + [E(X) for X in [P[0:n],Q[0:m]] if not blank(X)])`.

The latter alternative holds when both source slices contain no NUL. A NUL is not W, so a source containing it cannot be removed as blank. The retained order is `mv`, first slice, second slice. A nonblank slice is encoded in its **original** entirety; leading/trailing whitespace is not removed. Empty/all-W operands are omitted, so C can be just `mv` or have only one operand. This does not assert a valid `mv` invocation, interpretation as a pathname, escaping safety, lack of option interpretation, or successful movement of anything.

## Scope and actual bindings

The target is `artifacts/visor/captured/hl-visor`, SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. Complete byte/FDE extents, including padding, diagnostics and landing pads, are:

| Local name | Half-open VA range | Bytes | GNU/LLVM rows after standalone LOCK joining |
| --- | --- | ---: | ---: |
| request | `0x3a15d0..0x3a1777` | 423 | 90 |
| coordinator | `0x323b60..0x323d0c` | 428 | 113 |
| collector | `0x3e1920..0x3e1bea` | 714 | 169 |
| blank filter | `0x3a98d0..0x3a9b67` | 663 | 175 |
| quote | `0x6516e0..0x651be4` | 1,284 | 319 |
| join | `0x371b60..0x371d8b` | 555 | 141 |

The 4,067 bytes are retained to support one relation, not credited as new byte recovery. Three additional windows total 137 bytes: `0x417026..0x417046`, `0x41707d..0x417098`, and `0x3d8ee8..0x3d8f36`. These are selected caller/downstream context, not full-FDE theorems. The first two calls at `0x417040/0x417092` bind slot `0x7e5f78` to this request helper. Their register assignments are visible in the exports; the provenance and wider publication control flow are outside this theorem.

`observed/records.json` retains every selected RELA raw record, full raw FDE and referenced CIE, native byte digest/partition, and imported `memcpy` symbol bytes. RELATIVE records bind `0x7e5060 -> 0x6516e0`, `0x7e5f88 -> 0x3d8d70`, `0x7e4cc8 -> 0x87579`, and the opaque dependencies listed below. `0x7e4b68` is type 6, symbol 6, addend 0, with dynamic name `memcpy`. No target address is inferred from a misleading nearest-symbol label printed by objdump. `observed/transfers.tsv` inventories every call, branch, return and UD2 in all retained windows. Direct local branch destinations are instruction boundaries in both complete native partitions.

## UTF-8 blank predicate: `0x3a98d0`

The exact set recovered from comparisons and the 256 bytes at `0x87579` is

`W = {0009..000D,0020,0085,00A0,1680,2000..200A,2028,2029,202F,205F,3000}`.

The forward scan `0x3a9919..0x3a99a6` decodes one scalar and advances by its encoding length. For canonical encodings, the non-ASCII leading byte is C2..DF, E0..EF, or F0..F4; the observed masks/shifts yield the usual positional base-64 value. For three-byte leads the initial `&0x1f` is equal to `&0x0f` on E0..EF. The four-byte case additionally masks with 7. ASCII advances by one. This is not UTF-8 validation: the instructions read continuation bytes without first proving enough bytes exist. Valid canonical input is required.

At `0x3a99a9..0x3a99bb`, unsigned `(scalar-9)<5` or equality to `0x20` continues. Other ASCII stops. For page 0, `table[low]&1` is used; only indices `0x85,0xa0` have that bit. For page `0x20`, `table[low]&2` is used; exactly indices `00..0a,28,29,2f,5f` have that bit. The independent equalities at `0x3a99e2` and `0x3a9a02` add `0x1680` and `0x3000`. All other valid scalar values stop the scan.

The forward invariant is: RCX is the offset preceding the current scalar, RDX its ending offset, RSI its ending pointer, and RDI the immutable slice end. When a first non-W scalar is found, RCX marks its start. If all scalars are W, `0x3a9a20` sets RCX=RDX=0 and the eventual length is zero. Empty input reaches the corresponding zero-length case at `0x3a9a29`.

The backward scan `0x3a9a69..0x3a9ade` starts at the end and never crosses the already consumed first non-W scalar. For a negative final byte it inspects preceding bytes: signed comparison with `0xc0` separates valid continuation bytes `80..BF` (signed less than -64) from leading bytes C2..F4. Thus it takes exactly two, three or four bytes on the canonical domain. Its `&31/&15/&7`, `&63`, and shifts reconstruct the same scalar. Classification at `0x3a9ae1..0x3a9b53` is the same W predicate. R9 keeps the end pointer of the current backward scalar. A non-W stop sets `RDX := RDX-RSI+R9`, the offset just after that scalar; exhausting the backward suffix leaves RDX at the end of the first non-W scalar. Finally `0x3a9b5e..0x3a9b61` returns `(base+RCX,RDX-RCX)`.

Therefore the returned length is zero exactly for empty/all-W slices, and otherwise positive. The collector uses only that zero test. `algebra.py` independently enumerates 1,112,064 canonical scalar values, verifies their base-64 equations and the table predicate against the stated 25-member set. This is a finite arithmetic check, not evaluation of the native decoder or proof of arbitrary malformed input.

## Exact quote grammar: `0x6516e0`

This statement qualifies the fixed mode byte zero. Generic nonzero mode bypasses the NUL scan; no rejection guarantee is claimed for that branch. Empty input writes `(T,0xbc1e8,2)`, whose bytes are `27 27`, at `0x651abb..0x651ad3`. The collector will already have removed empty input on our path.

For positive length and mode zero, `0x651af4..0x651b12` compares each original byte with zero, stopping either at the first NUL or at the length. A NUL writes **only** first word `T+1` at `0x651b14..0x651b21`, then returns. The other result words are inactive and must not be read. This happens before any quote-buffer allocation. A completed NUL-free scan enters `0x651706` with the original pointer and length intact and initializes `(0,1,0)` storage.

For each remaining nonempty suffix define byte admission masks with bits 1=raw, 2=single, 4=double:

| Bit | Exactly allowed bytes |
| --- | --- |
| 1 | ASCII `+-./0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ]_abcdefghijklmnopqrstuvwxyz` |
| 2 | All bytes except apostrophe `27`, backslash `5c`, caret `5e` |
| 4 | All bytes except exclamation `21`, dollar `24`, caret `5e`, backtick `60` |

The raw masks at `0x6517b2/0x6517bf` are respectively `0x07fffffea7ffffff` and `0x07ffe80000000000`. The `0x40` select at `0x6517a7..0x6517ae` selects the appropriate half of the 128-bit membership set; bytes >=128 take `0x651810` and clear only bit 1. For ASCII, `b-33` within 0..63 indexes `0x8000000000000009` (clear double at !,$,backtick) or `0x0800000000000040` (clear single at apostrophe,backslash). Equality `(b-33)==0x3d` clears both quote bits at caret. These constants and all clear instructions are tied to native operand bytes in `pins.json`. The 1,792 byte/previous-mask cases in `algebra.py` confirm the stated sets, intersection shrinkage and least-set-bit choices. No guessed standard quoting library is used.

At `0x651768..0x65177d`, a **leading caret** begins a chunk with length 1 and mask 2. Otherwise the initial length is 0 and mask 7. Scan subsequent bytes by intersecting the current mask with their admission mask, until the end or the next intersection would be zero. At `0x651826..0x65182e`, the zero branch preserves the **previous** mask in AL and does not increment RDX; that conflicting byte belongs to the next chunk. The end case uses the final nonzero mask. A leading non-caret has a nonzero admission mask, while a caret has already been consumed by its special initialization. Hence every chunk has positive length. Length is at most the remaining byte count, so `sub rbx,rbp` cannot borrow at `0x651877`; zero-length and zero-choice diagnostics are unreachable under the invariant. Remaining length strictly decreases, proving termination for finite input with normal growth calls.

Choice uses the least set bit at `0x65183e..0x65184c`: raw first, then single, then double. For a chosen chunk X:

* Raw appends X unchanged (`0x651920..0x651947`). When this one raw chunk covers the whole remaining input and the output is still empty, `0x651867..0x65186f` instead returns `(T,original_pointer,original_length)` through `0x651b26`. Thus a wholly raw argument is borrowed; mixed arguments are built.
* Single appends `27 || X || 27`. The opening store is `0x6518c7`, the copy `0x6518f2`, and the closing store `0x651745`. The exceptional leading caret is included unchanged inside these bytes; no other caret lies in a single chunk because it would end the preceding scan.
* Double appends `22 || escape(X) || 22`. `escape` inserts `5c` before bytes `22,24,5c,60`, as the mask `0x4400000000000005` indexed by `b-34` at `0x6519bf..0x6519d7` establishes. The prefix store is `0x6519ed`; the original byte store is `0x6519a5`; closing quote is `0x651a2f`. Some of these escape cases cannot occur in a double-selected chunk because the admission rule excludes them, but the complete encoder rule still includes them.

The double loop's R13 is the offset at which the final original byte is stored, not the offset after it. Therefore closing at `[pointer+R13+1]` and final length `R13+2` agree with the opening quote, inserted escapes and all original bytes. R12 is reused for a byte during this loop and reset to zero at `0x651a19`; R13 is reset to 1 at `0x65174d` before the next mask scan. Those resets are needed for the high/low raw-mask construction; registers are not presumed constant across the entire body.

All chunks concatenate without an inserted separator. This definition is `E`. Examples include `E(a^b)=a'^b'`, `E(^^)='^''^'`, and original `20 61 20` producing `27 20 61 20 27`. These are exact constructed bytes, not a shell parser theorem. `algebra.py` checks 18 handwritten cases and 11,110 representative words against the declarative chunk grammar's progress, partition and size properties; it does not run a shell or native instruction sequence.

For chunk length k>=1, emitted size is k, k+2, or at most 2k+2, respectively; each is at most 4k. Consequently `|E(X)|<=4|X|` for positive input. Each local increment and `k+2` fits under the aggregate domain. Capacity-minus-length checks at `0x6518a1/0x651920/0x651960`, reserve calls at `0x651a47/0x651a6c/0x651a87/0x651aac`, and one-byte growth calls protect each append **conditional on the growth premise**. In particular, reserving k+2 does not by itself reserve every possible double escape: the per-byte checks/growth remain necessary. On completion `0x651add..0x651aef` writes the owned triple. Neither ordinary allocator capacity (0..T-1) nor borrowed T equals T+1 or T+2. The quote body does not produce T+2 in this domain.

## Record collection, sticky failure and ownership

At `0x323b7b..0x323b9e`, the coordinator stores the incoming mode pointer at local +0x30, a fresh sticky-failure byte zero at +7, and iterator fields `(begin,end,&mode_pointer,&failure_byte)` at +0x10..+0x28. The collector receives this iterator and a separate result object at `0x323bad`. These stack-address escapes require the preservation premises above; the proof does not infer safety merely from a syntactic lack of local stores.

The collector advances input descriptors by 16 bytes. First-loop `0x3e1995/0x3e1998` retains original pointer/length in R15/R13, calls the filter at `0x3e19a2`, and tests only RDX at `0x3e19a7`. If positive, it loads the mode pointer through the stored extra indirection, then passes **R15/R13** at `0x3e19b7/0x3e19ba` to the quote call. The later loop repeats this with original R13/RBP at `0x3e1a67..0x3e1a90`. Neither loop passes the trimmed pointer RAX or trimmed length RDX onward. This proves whole-original-slice encoding on both paths.

The result-tag tests happen **before** payload reads: first at `0x3e19c3..0x3e19e0`, later at `0x3e1a96..0x3e1ab3`. T+1 writes failure byte 1 (`0x3e1b24/0x3e1b57`) and returns the successfully collected prefix; first-loop failure returns `(0,8,0)`. T+2 skips the record without setting failure. That skip branch is fully present, but unreachable from this qualified mode-zero quote producer. Other results are stored as 24-byte triples in input order.

The first retained record allocates `0x60` bytes at `0x3e19ec..0x3e19f1`, sets capacity 4 and count 1, and stores its complete triple. Subsequent retained records are appended at `0x3e1af0..0x3e1b0d`. Exactly three input descriptors are supplied by the request, and `mv` is nonblank and wholly raw; thus this path non-vacuously contains its first borrowed record and uses count 1..3. The array-growth condition at `0x3e1ac7` tests current count against capacity 4 before another append; count is at most 2 when any remaining input could append. The `0x3f4a80` array-growth call is therefore unreachable for this caller, not assumed correct by analogy with another packet.

When sticky failure is 1, `0x323bb2..0x323c03` walks exactly the collected prefix. It skips triple capacity T and zero, and calls cleanup with pointer/capacity otherwise. The array itself is released if its capacity is nonzero at `0x323ca2..0x323cb9`. It writes only output word T at `0x323cbf`, leaving other words inactive, and does not join or invoke a shell helper. When failure is zero the coordinator also checks array capacity T at `0x323c17`; the actual collector produces only 0 or 4 on this fixed path, so that extra error branch is unreachable under the producer relation.

The successful path joins at `0x323c4d`, copies all three result words to the caller's output at `0x323c52..0x323c60`, then performs the same owned-vs-borrowed element cleanup and array cleanup at `0x323c63..0x323cf5`. Cleanup must preserve the copied output and its independently allocated payload. These guards alone do not prove deallocator validity, lifetime soundness under aliasing, or exception behavior.

## Exact join and length boundary

`0x371b60` consumes 24-byte triples and an address for the one-byte separator. Zero count returns `(0,1,0)` at `0x371bb7`, though fixed `mv` makes that branch unreachable here. For positive count k, `0x371b90` sums lengths with unsigned carry checks at `0x371b95`. It then adds k and decrements once (`0x371ba4..0x371ba7`) and tests the sign at `0x371baa`. Those latter two operations have no separate carry guards. We do **not** claim a correct arbitrary-count/arbitrary-length overflow interface from this sign test.

For this producer k<=3, `mv` contributes exactly 2 bytes, there are k-1<=2 separators, and the other encodings together contribute at most 4(n+m). Thus final `L<=4(n+m)+4<=2^63-4`; the temporary sum+k is at most L+1<=2^63-3. All additions, record offsets (at most 72), and the decrement are nonwrapping and L>=2. Carry and sign failures cannot occur in this domain. The mathematical sufficient bound is explicit: increasing the allowed aggregate input by one would make the coarse upper bound reach `2^63`, so that larger domain is not silently covered. This is a bound counterexample, not a constructed target allocation or failure trace.

At `0x371bdd..0x371bf9` the function allocates L bytes and records capacity L. The first copy takes first-record pointer/length (`+8/+0x10`) at `0x371c0c..0x371c3a`. For each later record, it writes the separator byte loaded at `0x371c7b` (actual `0x20` from `0x769e6`) at `0x371cf5`, then copies the next pointer/length (`0x371d01/0x371d06`) at `0x371cbe`. The index increases by 24 until the computed end. Prefix-length induction shows that before each separator there is at least one remaining separator byte, and after it there is at least the next record's length. Since lengths remain stable, the first-copy reserve, separator growth and later-copy reserve branches (`0x371d23`, `0x371ce0`, `0x371c8a`) are all unreachable on this fixed successful path. The final triple is `(L,allocated_pointer,L)` at `0x371c4e..0x371c61`.

## Request, errors and downstream limit

The request retains its four incoming words in R12/R15/R14/RBX before preflight. `0x3a1605` tests the preflight low DWORD for 2. If equal, it copies the error payload word into the local error object and sets a full tag 2 at `0x3a16ef..0x3a16fc`; cleanup `0x3a90d0`, formatter through `0x7e4c20`, and factory `0x3f5ca0` follow. This branch makes no builder/shell call. Otherwise it copies `0xb0` bytes and rechecks full QWORD 2 at `0x3a1628`. Under faithful stable memcpy, full 2 cannot follow low-DWORD-not-2, but the native branch remains recorded; no branch was removed from the export.

The admitted path constructs three descriptors at local +0x30,+0x40,+0x50 from literal `6d76` at `0x795ec`, original P/n, and original Q/m. It passes begin +0x30, end +0x60 and mode-byte address +7 containing 0 to `0x323b60`. A returned first word T is detected by NEG overflow at `0x3a1686..0x3a1689`; for a 64-bit operand this flag is set exactly at T. That branch calls opaque `0x3f66d0` and returns its RAX. No payload words are read and no shell helper is called. Thus NUL is propagated through T+1, sticky byte 1, T, and this no-shell branch; the factory's result value itself is not qualified.

On successful join, `0x3a1699..0x3a16a9` copies `(L,pointer,L)` to local +0xe0,+0xe8,+0xf0 and `0x3a16b1` writes option byte 1 at +0xf8. `0x3a16c1` calls `0x3d8d70` through its actual RELATIVE slot. After return it conditionally drops the command allocation if capacity is nonzero; here L>=2. RAX is saved in RBX at `0x3a16d4` and restored at `0x3a16dd`, so under normal preserving cleanup the request returns the helper's unmodified word. This does not classify that word or prove that helper spawned a process.

The prior [shell-command packet](../RE-013-visor-shell-command/README.md) ([PR 1266](https://github.com/lalalune/hyperliquid-source/pull/1266)) owns the downstream process/request analysis. The prior [format-requests packet](../RE-013-visor-format-requests/PROOF.md) ([PR 1345](https://github.com/lalalune/hyperliquid-source/pull/1345)) already proves, under its own selected formatter branch and allocation premises, construction of `(C) > /dev/null 2>&1` for nonzero option. The context here merely binds the option=1 and stream `0x6bf04` to that existing result. It is **not an unconditional wrapper theorem**: that helper has an earlier raw substring test for `2>&1`; a quoted operand such as `E(2>&1)='2>&1'` still contains those four bytes. No new complete substring-scanner proof is made here. The helper's prepared path is the separate scope of [PR 1375](https://github.com/lalalune/hyperliquid-source/pull/1375); neither that unmerged packet nor our separate metadata-publication packet is a dependency.

## Complete-body boundaries and opaque calls

Every ordinary local decision is accounted for above: preflight/error/result/capacity request branches; coordinator sticky/array/cleanup branches; collector empty/blank/two tags/first allocation/append/failure branches; both blank scans and scalar/table branches; quote empty/mode/NUL/masks/choice/append/reserve/result branches; join empty/sum/sign/allocation/copy/append branches. The complete exports also contain exception landing pads and diagnostics. Their retention is not a stronger proof:

| Calls outside the six-body relation | Status |
| --- | --- |
| `0x686d10` via `0x7e5608` | Opaque preflight result contract, not filesystem behavior. |
| `0x70bf30` via `0x7e4b60` | Fresh allocator premise, including nonzero valid storage on the selected success path. |
| `0x651670`; `0x2be910` via `0x7e4bc0` | Prefix-preserving reserve/growth premise for quote appends. No lower-reallocator proof. |
| `0x3f4a80` | Collector/join growth branches are unreachable for the fixed bounded caller; arbitrary callers remain unqualified. |
| `0x714530` via `0x7e4b80` | Normal, storage-compatible cleanup with live-output preservation. |
| `0x3a90d0`, `0x2bebb0` via `0x7e4c20`, `0x3f5ca0`, `0x3f66d0` | Error branch operations are opaque; selected call/no-call order is proved, result discriminants are not. Formatter callback address `0x32cf10` is merely passed by the error path. |
| `0x3d8d70` via `0x7e5f88` | Receives the proved request; behavior/return word remains an explicit boundary here. |
| `0x2beaf4` via `0x7e4b40`; `0x49bd20` via `0x7e4ca0` | Allocation/overflow diagnostic branches excluded by the success and size domain. Do not assume their return shape or nonreturn solely from neighboring code. |
| `0x49ae00` via `0x7e4c00`; `0x49ade0` via `0x7e4c60` | Quote diagnostics reached by out-of-invariant length/choice states; ordinary valid chunks cannot reach them. UD2 follows their shared tail. |
| `0x31a4f0`, `0x3dba40`, direct `0x7a6820` | Landing-pad cleanup/unwind calls retained, not semantically qualified. The objdump `_Unwind_Resume` label is not needed for the theorem. |

In particular the join's diagnostic code can fall into other code if opaque diagnostics unexpectedly return. This packet does not claim those paths return a well-formed result. The finite checks support arithmetic and byte binding; the full conditional native relation remains this manual proof, open to independent review.
