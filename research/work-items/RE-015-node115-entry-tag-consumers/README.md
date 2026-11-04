# RE-015 — node 115 entry tags downstream of the exit reader: no per-tag consumer; the {6, ...} form unwrap-panics, the plain out struct is registered globally

Question (the recorded next question of the set-initializer
packet, RE-015-node115-set-initializer / #2648):

> What consumes the entry tags 0/1/2/3 downstream of the exit reader
> (the 0x50-byte out struct versus the {6, ...} form, and the
> destination object at `[rsp+0x278]`)? (Carried over unchanged from
> the merge-delegate packet; the set-initializer half of its next
> question is answered by this packet.)

The original wording in the merge-delegate packet
(RE-015-node115-merge-delegate / #2615) ends its next question with
the same sentence: "What consumes the entry tags 0/1/2/3 downstream
of the reader (the 0x50-byte out struct versus the {6, ...} form,
and the destination object at `[rsp+0x278]`)?"

Answer, in one line: **nothing downstream reads an individual tag
value.** The exit reader branches only on the merged entry vector's
count; a nonzero count turns the whole call into a Rust
`Result::unwrap` panic in the consumer (the {6, ...} form is the
Err variant, carrying the entry vector as its value), and a zero
count delivers the plain 0x50-byte out struct to the destination at
`[rsp+0x278]` — the consumer's own `rdi` argument, a scratch buffer
in its sole caller's frame, which that caller hands to a registrar
that wraps and globally registers the struct. The only other
consumers of the entries are the Err value's Debug formatting
(vtable-dispatched) and the entry vector's drop, which frees every
entry through one uniform path gated on tag <= 3.

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| exit consumer | `0x15a3b90..0x15a6509` | 10617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |
| sole caller wrapper | `0x15a6510..0x15a6674` | 356 | `f89a14d39fba3e107a6f843895ed7bc4f718f8e462a3977f4b152265d2586f79` |
| entry vector drop | `0x15ac470..0x15ac4f0` | 128 | `ab4363fc438acb9c0c21599a6f8b1f03c00f35427b75eb0f824e60527e7990a7` |
| unwrap-failed helper | `0x1680c30..0x1680c82` | 82 | `2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a` |
| panic helper | `0x1680e80..0x1680eac` | 44 | `28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3` |
| registrar | `0x474f6a0..0x474f7ff` | 351 | `a26fb8c2033f2f6c6242755b86e5377a13bce19b1459d1761ddf9b56c8132c1e` |
| refcount wrap ctor | `0x4742470..0x4742595` | 293 | `fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c` |

The consumer body hash is the same one the assembled-record
readers, derived-byte-callee and flag-group-first-byte packets pin
as a boundary; the map-owner packet first recorded the wrapper as
the consumer's only direct caller and a hash-pinned boundary. This
packet traces the consumer's exit block, the wrapper body, and the
chain past both.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| exit reader | `0x4749ab0..0x4749d71` | `6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb` |
| Err Debug fmt | `0x15b4420..0x15b4545` | `c64e11015ce72574b32d2da1bd6190eba3fc17807863d0c07bd4f1086ea3059f` |
| payload ctor | `0x4741180..0x4741869` | `8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a` |
| registrar lookup | `0x474fb00..0x474fcab` | `affacd8e00f02955fea148d136d213e52d070aeaffd068ee8755e4c0a47480f8` |
| registrar key | `0x47418d0..0x474195a` | `577008e25225f28944bdc6b56ae5cc42a5a35a33cfe202a64b89fa0dde35adbb` |
| Err fmt dispatch shim | `0x1687260..0x1687270` | `73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe` |
| &str fmt | `0x1687590..0x16875a3` | `a787ddffe7b8a5b8fee9b747ab817d7d900e59e2148ab84a9055d174060b80d6` |

Slot bindings used (all RELATIVE): unwrap-failed `0x64df6a0` →
`0x1680c30`; panic entry `0x64df6b8` → `0x1680e80`; exit reader
`0x64e1480` → `0x4749ab0`; registrar `0x64e1488` → `0x474f6a0`;
merge delegate `0x64eafd8` → `0x4748500`; wrap ctor `0x64eaf70` →
`0x4742470`; dealloc `0x64df4a0` → `0x635de30`; cleanup `0x64df4c0`
→ `0x1680cab`; assert-fail `0x64df770` → `0x1680bd0`; global cell
`0x64eaf08` → `0x64ffef8`; registry insert `0x64eaef0` →
`0x47359e0`; alloc `0x64df480` → `0x6355830`; alloc-fail
`0x64df490` → `0x141e251`; panic runtime `0x64e1f30` → `0x5c826c0`;
weak drop `0x64eaf50` → `0x474b3f0`.

## Trace

### The reader's two out forms

The exit reader `0x4749ab0` (owned by the assembled-record-readers
packet; its body hash is re-pinned here as a boundary) calls the
merge delegate through slot `0x64eafd8` with its temp at frame
`[rsp+0x70]`, then loads the temp's entry count word (temp+0x60,
at `0x4749b1d`) and tests it (`0x4749b25`):

- count == 0: the copy arm at `0x4749cc4` copies temp[0..0x50]
  verbatim into the out union (the reader's `rdi`).
- count != 0: the reader stores the temp's entry vector header
  into the out union — `[out+0x08] = temp+0x50` (cap),
  `[out+0x10] = temp+0x58` (buffer), `[out+0x18] = temp+0x60`
  (count), at `0x4749b2e` onward — and finally writes the
  discriminant: `mov QWORD PTR [rbx], 0x6` at `0x4749b3a`.

No tag word is loaded on either arm; the only branch input is the
count. The per-tag production semantics stay upstream, in the
delegate (merge-delegate packet: 0 = vecA duplicate, 1 =
third/sub-vector non-member, 2 = vecB duplicate, 3 = vecB
colon-scan hit).

### The consumer's branch and the [rsp+0x278] destination

The consumer `0x15a3b90` calls the reader through slot `0x64e1480`
at `0x15a592a` with out = `&[rsp+0x20]`, the saved pair at
`[rsp+0x240]`, and the empty third vector at `[rsp+0xc0]`
(initialized to the empty `{0, 8, 0}` header at `0x15a58f2`). It
then compares the out word against 6 (`cmp DWORD PTR [rsp+0x20],
0x6` at `0x15a5930`; `je 0x15a5b8c`):

- word == 6: the assertion arm below; the destination is never
  written.
- word != 6: the consumer loads the destination pointer from
  `[rsp+0x278]` (`0x15a5940`), stores the word at out+0x40 to
  `[dest+0x40]`, then copies out[0..0x40] over `[dest..dest+0x40]`
  with four movups stores, and returns.

The `[rsp+0x278]` slot is accessed exactly twice in the whole
10617-byte body (byte census in the tool): the prologue save
`mov [rsp+0x278], rdi` at `0x15a3ba1` and the exit load. The
destination object is therefore the consumer's own first argument,
whatever its caller passes — traced one level up in the last
section.

### The {6, ...} form is a Result Err, and it unwrap-panics

The assertion arm at `0x15a5b8c` rebuilds a 24-byte vector header
at `[rsp+0xc0]` from the out union (`[rsp+0x28..0x38]` = {cap,
buffer}, `[rsp+0x38]` = count) and calls the unwrap-failed helper
through slot `0x64df6a0` at `0x15a5bc8` with:

- `rdi` = `0x468b3f`, `esi` = 0x2b (43): the message bytes are
  `called \`Result::unwrap()\` on an \`Err\` value`;
- `rdx` = `&[rsp+0xc0]`: the Err value (the entry vector header);
- `rcx` = `0x63ffe00`: the error's vtable — drop `0x15ac470`
  (RELATIVE addend at +0x00), size 24 at +0x08, align 8 at +0x10,
  Debug fmt `0x15b4420` (RELATIVE addend at +0x18);
- `r8` = `0x63ffb30`: the call-site Location — file pointer
  `0x43ab16` = `base/src/log/handle.rs` (length 22), line 167,
  column 60.

The helper `0x1680c30` stores the message pair and the error
pointer/metadata pair, builds a format Arguments with the &str
formatter `0x1687590` and the dyn-Debug dispatch shim `0x1687260`
(which tail-jumps through the vtable's +0x18 word, i.e. to
`0x15b4420` for this error), and calls the panic entry `0x1680e80`
through slot `0x64df6b8`. The panic helper packages
{&arguments, Location, kind word 1} and calls the panic runtime
through slot `0x64e1f30`; the arm falls through to the `ud2` at
`0x15a5c77`. The arm never returns, so on this path the entry
vector is consumed in exactly two ways: its Debug rendering inside
the panic message (body hash-pinned as a boundary; what it prints
beyond the header is not claimed), and its drop through the
vtable.

The consumer contains two more unwrap sites with the same message
(call sites `0x15a59ef`, `0x15a5a72`, vtables `0x63ffde0` /
`0x63ffe40`, 8-byte errors) — different Results in the same handle
function, pinned in the tool as context rows.

### The entry vector drop treats all four tags alike

The vtable drop `0x15ac470` takes the header {cap at +0x00, buffer
at +0x08, count at +0x10} and walks the buffer at stride 0x20. For
each entry it compares the tag word at entry+0x00 against 3
(`cmp DWORD PTR [r12-0x10], 0x3` at `0x15ac4a9`, unsigned `ja`
skips): entries with a tag above 3 are skipped, and for every
entry with tag <= 3 whose +0x8 word is nonzero it calls the
dealloc slot value (loaded from `0x64df4a0` at `0x15ac48d`) with
(ptr = entry+0x10, size = entry+0x8, align = 0). The entry word at
+0x18 is never loaded. After the walk, the buffer itself is freed
at `cap << 5` through the same slot (tail jump at `0x15ac4e0`).
There is no per-tag branch: tags 0, 1, 2 and 3 share one path, and
the tag word serves only as an upper-bound sanity gate.

A binary-wide direct-call census (in the tool) finds exactly one
direct call site to `0x15ac470`: `0x15a6042`, inside a landing pad
of the consumer itself, which loads `rdi = &[rsp+0xc0]` — the same
frame slot the assertion arm rebuilds the header into — and
resumes unwinding after the call. The pad's exact protected range
is not pinned (see Limits).

### Where the plain form goes: wrapper, registrar, global registry

The consumer's sole direct caller in the binary (census in the
tool: one call site, `0x15a6556`) is the wrapper `0x15a6510`. It
first derives a nonzero id scalar into `[rsp+0x3c]` (helpers
through slots `0x64e0990`/`0x64e0ab8`; a zero id takes an
assert-fail exit through slot `0x64df770`), then calls the
consumer at `0x15a6556` with `rdi = &[rsp+0x48]` — a 0x50-byte
scratch buffer in its own frame — `rsi` = its record argument, and
`edx` = the id. That scratch is the `[rsp+0x278]` destination
object.

After the consumer returns, the wrapper:

1. reads a flag byte at `[record+0x4c]` and builds a 0x28-byte
   side value at `[rsp+0x10]` (from two `.data.rel.ro` statics
   when the flag is set, else zero);
2. calls the registrar `0x474f6a0` through slot `0x64e1488` at
   `0x15a6596` with `rdi = &[rsp+0x48]` (the filled scratch);
3. if the registrar returns 0, the wrapper itself unwrap-fails
   through slot `0x64df6a0` (call site `0x15a663f`) on a zero-size
   error at `[rsp+0xf]`;
4. otherwise it assembles its own out object (its `rdi`): a
   verbatim copy of the record argument's first 0x50 bytes at
   +0x00, the registrar's return word at +0x50 (`0x15a65e9`), the
   side value at +0x58..+0x80, and the id scalar at +0x80, and
   returns the object pointer.

The registrar never reads the scratch's fields. It forwards the
pointer unchanged as `rdi` to its first callee, the wrap
constructor `0x4742470` through slot `0x64eaf70` at `0x474f6ad`.
The constructor passes the pointer on as `rsi` to the payload
constructor `0x4741180` (direct call at `0x474248e`, with a static
at `0x6494c78` and flag 1), which builds a 0x68-byte payload in the
constructor's frame: its head loads the struct words at +0x20
(`0x47411b3`), +0x30 (`0x47411a7`), +0x38 (`0x47411cb`) and +0x48
(`0x47411bf`) and scales the +0x30 word by 0x40-byte records
(`shl rbp, 0x6` at `0x47411df`) — the first field-level reading of
the out struct anywhere downstream. The constructor boxes the
payload as a 0x78-byte refcounted object ({1, 1} counts + payload)
and returns a 0x18-byte wrap allocation. Back in the registrar,
the lookup helper `0x474fb00` and key helper `0x47418d0`
(boundaries) derive a word from the wrap, which the registrar
stores into the global cell behind slot `0x64eaf08` (`mov
[rax], r14` at `0x474f724`); it then allocates an 8-byte node
holding the wrap pointer and inserts it through slot `0x64eaef0`
(registry insert `0x47359e0`), and returns the wrap pointer — or 0
when the insert reports failure.

## Limits

- The payload constructor `0x4741180` (1769 bytes) is a boundary:
  only its head field loads and the 0x40 record stride are pinned.
  Which fields of the 0x50-byte struct land where in the 0x68-byte
  payload, and whether it iterates the vectors' elements, is the
  next question below.
- The Err Debug fmt body `0x15b4420` is a boundary: the packet
  pins that the panic formats the 24-byte entry vector header
  through it, not what text it renders for the entries.
- The landing pad holding the drop call at `0x15a6042` is pinned
  as a pad of the consumer acting on the `[rsp+0xc0]` header; its
  exact LSDA protected range is not decoded in this packet.
- The wrapper's id helpers (slots `0x64e0990`, `0x64e0ab8`), the
  registrar's lookup/key helpers, and the registry insert target
  are hash- or slot-pinned boundaries; who reads the globally
  registered object after the registrar is not traced.
- The delegate-side meaning of the tags is taken from the
  merge-delegate packet, not re-derived here. No captured code
  executed, no runtime value or reconstruction gate is claimed.

## Next question

What does the payload constructor `0x4741180` do with the out
struct's three vector headers — which of the 0x50 bytes become the
0x68-byte registered payload, and does it walk any vector's
elements? What does the Err Debug fmt `0x15b4420` render for the
entry vector when the unwrap panic fires? And who reads the
registered object out of the global cell behind slot `0x64eaf08`
afterwards?
