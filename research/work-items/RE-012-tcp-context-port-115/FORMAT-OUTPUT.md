# RE-012: changed-result formatter and append boundary on node #115

- Component `transport`, task RE-012; owned files are this evidence directory.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: what does `0x141e3a0`, called by the two changed-result branches
  of `0x1546570`, write before the lookup returns to the outer handoff?
- Status: selected static caller/template/output join, with nested callback
  and allocation effects still open. No implementation or gate is completed.

Both actual templates take a formatter path that starts with a local header
**`{capacity=0, pointer=1, length=0}`**. The formatter's initial allocation
call is bypassed. On a successful dispatcher return, it writes exactly
**24 bytes** to the lookup's designated result buffer. This does not mean
formatting is allocation-free: callbacks and literal writes can grow the
buffer before that result is copied.

The two templates and their argument bindings are new caller-specific
evidence. Existing RE-015 formatter, dispatcher and append traces are
revalidated against #115 rather than credited as newly recovered bodies.

## Captured bytes and reused evidence

[format.py](format.py) checks the full capture digest, FDE extents, body
hashes, instruction pins, relocations and explicit destination census against
[format-spec.json](format-spec.json). Raw GNU/LLVM output, Capstone rows,
commands and versions are retained in [format/records.json](format/records.json).

| Complete FDE interval | Bytes / instructions | Role |
| --- | ---: | --- |
| `0x1546570..0x15466f3` | 387 / 85 | Revalidated lookup caller |
| `0x141e3a0..0x141e538` | 408 / 122 | Formatter entry and 24-byte result |
| `0x1680500..0x16806c0` | 448 / 138 | Template dispatcher |
| `0x141e8f0..0x141e951` | 97 / 36 | Table `+0x18` append method |
| `0x141c980..0x141c9f2` | 114 / 35 | Capacity-growth request and installation |
| `0x15ebba0..0x15ebbb3` | 19 / 5 | Pair-reading callback |
| `0x150ce90..0x150cf4d` | 189 / 43 | DWORD-reading callback |
| `0x150cf50..0x150cfdb` | 139 / 40 | BYTE-reading callback |

The context capture is **1,801 bytes / 504 instructions**, not new-function
coverage or a binary-equivalence denominator. FDEs support bounded exports;
they do not alone establish source function boundaries. Both native lookup
exports match the preceding supplement byte for byte.

The following existing static trace functions were run on the authenticated
capture and compared exactly with their retained record keys:

- [Formatter consumer](../RE-015-node115-flag-group-format/README.md):
  `flag_group_format_static.consumer_trace`, key `consumer`.
- [Dispatcher](../RE-015-node115-flag-group-write-target/README.md):
  `flag_group_write_static.write_target_trace`, key `write_target`.
- [Append method](../RE-015-node115-table-method/README.md):
  `table_method_static.method_trace`, key `method`.

Module, record and manifest hashes are retained. This is a replay of those
three named trace functions, not of their global xref searches, simulation
worksheets or complete original test suites. Imported evidence is unchanged.

## Actual templates and callback ordinals

Let LS denote the lookup's post-prologue stack, C its retained context, K
the input DWORD and B the classifier byte from [LOOKUP-RESULT.md](LOOKUP-RESULT.md).
The argument array at LS+0x10 uses 16-byte entries: value pointer, callback.

| Branch / formatter call | Template VA and exact bytes through terminator | Token order |
| --- | --- | --- |
| Plain / `0x15466aa` | `0x43aa84`: `c0 01 2f c0 00` | argument 0, `/`, argument 1 |
| Tagged / `0x154661a` | `0x43ab07`: `c0 08 2f686f75726c792f c0 01 2f c0 00` | argument 0, `/hourly/`, argument 1, `/`, argument 2 |

Here C0 selects the next sequential argument. A positive short token gives
the length of following literal bytes; zero terminates the template. The
collector deliberately accepts only this observed subset. Adjacent rodata
is not included. The literal `/hourly/` is observed text, not proof of a
clock type, timezone or calendar encoding for the arguments.

| Ordinal | Value storage and callback binding | Direct callback input reads / open continuation |
| --- | --- | --- |
| 0, both branches | LS+0x58, copied 16 bytes from C+8; LEA selects `0x15ebba0` | Two QWORDs; forwards them as pointer/length to `0x167fa70` through `0x64df720` |
| 1, both branches | LS+0xc, DWORD K; `0x64e0b68 -> 0x150ce90` | DWORD; nested dispatch through `0x64df6f0`, including callback `0x150e1d0` |
| 2, tagged only | LS+0xb, BYTE B; `0x64e0b70 -> 0x150cf50` | BYTE; local digit-buffer writes, then `0x167e9d0` through `0x64dfa00` |

The latter callees are identified boundaries, not transitively closed
implementations. No rendered date/string type is assigned to K. The copied
pair can retain a pointer into other storage; copying it does not prove
independent ownership or non-aliasing of its referenced bytes.

## Initial capacity and dispatcher behavior

At formatter entry, RDX is the even, stack-aligned argument pointer. Thus
the low-bit test at `0x141e3bc` takes the template-scan path. Both templates
begin with a placeholder, before any literal bytes; their literal totals
are respectively 1 and 9. At `0x141e45b..0x141e477`, that combination selects
capacity zero. The call at `0x141e47c` through the allocation slot is skipped.

At `0x141e49d..0x141e4a5` the formatter writes capacity 0, pointer 1 and
length 0 into the local three-word header. Pointer 1 is an encoded initial
value, not a byte buffer that may be dereferenced. The formatter calls
`0x1680500` through `0x64df6f0` at `0x141e4be`, passing the header, table,
template and original argument array.

The six words at table `0x63f3d50`, after applying pinned relocations, are:

```text
+0x00  0x141c960     +0x08  0x18          +0x10  8
+0x18  0x141e8f0     +0x20  0x141e7e0     +0x28  0x141ed80
```

The two scalar words are stored in the file and have no relocation; the
four function words have unique `R_X86_64_RELATIVE` records. Their presence
does not prove every table member is invoked on this route.

The dispatcher caches table+0x18. On a literal it calls that method at
`0x1680575` with `(header, literal pointer, literal length)`. On C0 it loads
the next 16-byte argument entry, builds a 24-byte stack descriptor containing
the header pointer, table pointer and default specification `0x60000020`,
and calls the entry's callback at `0x1680666`. The next index is incremented
only on the selected successful continuation. No other template grammar
cases are needed for these two callers.

All these continuations require **AL=0 from each invoked writer/callback**.
The dispatcher returns zero at the terminator; a nonzero callback result
takes its error result. The formatter tests this byte at `0x141e4c6`; only
zero reaches its ordinary result copy. Diagnostic/unwind behavior is not
closed by the normal-edge claim.

The finite edge tapes in the records enumerate each encoded scan/dispatch
edge, including repeated visits, and require exact call order with no unused
decisions. They evaluate no machine registers or captured code. They are
conditional static paths, not evidence that a live invocation takes them.

## Append, growth and the remaining allocation boundary

The append header uses QWORD capacity at +0, buffer at +8 and length at +16.
For a valid header `0 <= length <= capacity`, `0x141e90e` compares the
unsigned request against remaining capacity:

- A fitting zero request skips memcpy and still stores the unchanged length.
- A fitting positive request calls imported `memcpy` at `0x141e91f` with
  `(buffer+length, source, request)`, then stores `length+request` at +16.
- An insufficient-capacity request calls `0x141c980` at `0x141e943` with
  `(header, length, request)`. The source pointer is saved across this call.
  On return it reloads length and rejoins the copy, without a second capacity
  test or a zero-length skip on that rejoin.

At `0x141c98b`, the grow helper adds length and request and branches on
unsigned carry. It computes a requested capacity equivalent to
`max(8, (2*old_capacity) modulo 2^64, length+request)` on the no-carry path.
Doubling itself has no overflow check in this body. The scalar worksheet
restricts old capacity to at most `2^63-1`, so doubling does not wrap.
It does not assume the allocator accepts the resulting size.

The call at **`0x141c9bd -> 0x141e0e0`** receives a local output pointer,
old capacity, old buffer pointer and requested capacity. If its local result
DWORD is not 1, the grow helper installs result+8 as the new buffer and the
requested capacity as header+0. Its own stores leave length unchanged.
This encoded success branch alone is not proof of allocation success,
preserved contents, valid ownership or valid capacity bounds.

Ten scalar cases cover empty, zero, exact-fit, one-over, 8/9-byte minimum,
doubling, larger request and high-capacity arithmetic. Four finite paths
cover zero-fit, positive-fit, positive-growth and grow-return (23, 27, 33
and 29 instructions before RET). No allocator or memcpy is executed.
Source/destination validity, non-overlap, allocation contracts and normal
callee returns remain explicit premises.

## Twenty-four output bytes and the tracked outer word

On dispatcher success, `0x141e4cc` writes the length QWORD to output+16 and
`0x141e4d4` writes the first two header words to output+0..+16. This is a
24-byte header result; payload bytes live behind its buffer pointer.
The result can reflect allocations and writes performed during dispatch.

Using the prior stack join, LS=OS-0x180. The formatter's RBP is LS-0x10,
so its local header is **OS-0x1d0**; the output designated by lookup is
**LS+0x40 = OS-0x140**. Both 24-byte intervals are disjoint from the tracked
word `[OS+0x188,OS+0x18a)` under valid, distinct, nonwrapping stack storage.
The lookup subsequently copies this triple into its wider result as
documented previously, including the still-unwritten plain output byte +5.

The seven bodies besides the already-censused lookup have **29 lexical
explicit memory stores**. Dispatcher stores are local; formatter has local
header stores and two result stores; append/grow update the header. Small
callback bodies have local explicit stores or none. This census excludes
implicit stack writes, calls and transitive callee effects. It cannot prove
that allocator writes, nested callbacks or aliased payload destinations
preserve the outer word. No general helper-purity claim is made.

## Verification and next bounded question

With the existing native tools and Python environment on PATH, reproduce
into fresh directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/format.py --out work/context-format-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/format.py --out work/context-format-optimized
```

Normal and optimized exports are compared as raw bytes. All **93 negative
and scope controls** reject: 14 anchor-byte changes, two template changes,
four table-byte changes, 34 changed/duplicate relocations, eight truncated
FDEs, four store-census changes, six malformed/unsupported templates, six
excluded formatter/dispatcher edges, four excluded append/grow edges,
six invalid growth inputs, three output-alias intervals and two wrong
captures. Body digests can reject corrupt instructions before their anchors.
Controls validate the collector's stated boundary; they do not establish
that invalid runtime states are unreachable.

[format-validation.json](format-validation.json) records results, source
hashes and retained local log hashes. The 34 focused existing tests pass.
The prior lookup collector is replayed byte for byte; three earlier static
trace records are revalidated. GNU/LLVM and Capstone agree over every
captured byte, without normalization masks. These checks do not replace
full semantic equivalence or an independent review.

The stale generated README catalogue failure remains. The earlier full
suite is incomplete with recorded failures, and the prior TLS suite has a
Windows metadata-path mismatch; neither is rerun or claimed green here.
All 92 full-scope gates remain false. No captured execution/emulation,
network action, Rust implementation, hosted CI, commit or push occurred.

The [allocation-result follow-up](ALLOCATION-RESULT.md) now bounds
**`0x141e0e0`**'s six result paths, size rejection and grow/error consumers.
The allocator callees still own unclosed payload/lifetime effects. Keep
nested formatter callbacks and the parent continuation `0x25f0250` as
separate unresolved side-effect boundaries.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
