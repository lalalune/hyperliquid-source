# RE-015: node 115 callee 0x15ae430 of the derived flag byte

```text
Task: RE-015
Function: 0x15ae430
Topic: derived-byte callee behaviour
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 scratch-name-pair packet established that the
large consumer `0x15a3b90` passes a four-byte flag group to the callee
`0x15ae430` and left open what the derived byte `[rsp+0x15]` does inside
that callee. This item traces exactly that question. The derived byte
itself is never read inside the callee: the consumer spends it before
the call, selecting which 24-byte record the callee receives. This
packet proves the selection on the consumer side and the record's fate
on the callee side, for both byte values.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| callee | `0x15ae430..0x15ae5ae` | 382 | `4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf` |
| consumer_large (boundary) | `0x15a3b90..0x15a6509` | 10,617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |

Measured denominator: two complete FDEs, **10,999 bytes** (382 + 10,617).
Only the callee's 382 bytes are retained as a disassembly export; the
consumer is pinned by its body hash (the same value recorded by the
scratch-name-pair packet) plus byte pins at every derived-byte site,
each validated as a native instruction start during generation. The
callee is reached from exactly four direct call sites, all inside
consumer_large (`0x15a3f5f`, `0x15a401e`, `0x15a4263`, `0x15a431c`); no
relocation addend and no data occurrence references its address.

## Trace stages

1. **Consumer selection (the derived byte's only consumption).** In
   consumer_large each field block tests bit 0 of the derived byte at
   `[rsp+0x15]` (`0x15a3f1f` and `0x15a4220`, `test BYTE PTR [rsp+0x15],
   0x1`). Bit 1 stores only the sentinel `0x8000000000000000` as the
   record's first qword (`0x15a3f2a`, `0x15a422b`); bit 0 stores a full
   register record `{r14, r15, rbx}` (`0x15a3fd2...`) or `{r14, r15,
   [rsp+0x78]}` (`0x15a42cd...`). The record pointer in `rdx` is
   `&[rsp+0xc0]`, the flag-group pointer in `rcx` is `&[rsp+0x14]`, the
   output pointer in `rdi` is `&[rsp+0x158]`, and the auxiliary pointer
   in `r8` is `&[rsp+0x13c]`, at all four call sites.
2. **Argument provenance.** The `rsi` argument of all four calls is the
   word at `[rsp+0x1a8]`, computed once at `0x15a3c34..0x15a3c42`:
   `lea rdx,[rsi+0x30]`; `cmp rdi(0),[rsi+0x30]` sets overflow exactly
   when the input qword at `+0x30` equals the sentinel; `cmovo` then
   stores 0, otherwise the field address. So `rsi` is 0 iff that input
   qword is the sentinel — the same neg-overflow idiom the callee's
   guard uses.
3. **Entry split.** The callee saves the record pointer (`rbx = rdx`,
   `0x15ae43d`) and the output pointer (`r14 = rdi`, `0x15ae440`), then
   tests `rsi` (`0x15ae443`). If `rsi == 0` it goes straight to the copy
   path: the 24-byte record is copied verbatim to the output
   (`0x15ae53f`, `0x15ae547`) and the function returns — no drop, no
   calls. The byte-selected record becomes the output itself.
4. **Construction path (`rsi != 0`).** The callee stores a 24-byte pair
   `{rsi, rcx (flag-group pointer), [0x64e1490] = 0x16035e0}` at
   `[rsp+0x8]`, calls through slot `0x64df6e8` (bound to `0x141e3a0`)
   at `0x15ae476` with the constant value `0x43b857`, calls through
   slot `0x64df650` (bound to `0x141cc40`) at `0x15ae491`, drops the
   first call's result word through slot `0x64df4a0` (bound to
   `0x635de30`) at `0x15ae4a6` if nonzero, builds a 48-byte record
   `{&pair, 0x1500960, &[rsp+0x58], 0x1598e40, r8 argument,
   [0x64e0b68] = 0x150ce90}` at `[rsp+0x28]`, calls slot `0x64df6e8`
   again at `0x15ae4f5` with the constant value `0x440e47`, writes the
   24-byte result at `[rsp+0x10]` to the output (`0x15ae4fb`,
   `0x15ae504`), and drops the second call's result word at
   `0x15ae51e` if nonzero. The flag-group pointer is only stored and
   handed onward inside these structures; the callee never
   dereferences it.
5. **Record drop guard.** On the construction path the input record is
   dropped under a pinned guard at `0x15ae524`: `c = [rbx]`, `neg c`;
   `jo` (taken when `c` is the sentinel, whose negation overflows) and
   `jae` (taken when `c == 0`, whose negation clears the carry) both
   skip the drop; otherwise the callee calls the dealloc slot with
   `rdi = [rbx+8]`, `edx = 0` (`0x15ae537`). The three unwind pads
   repeat the same conditional drops and the same guard (copy at
   `0x15ae58d`, drop call `0x15ae5a0`) before `_Unwind_Resume`.

## Traced result

The derived byte's bit 0 chooses the record, and the record's first
qword decides its fate under the guard:

| Record first qword | Guard | Dealloc of `[record+8]` |
| --- | --- | --- |
| `0x8000000000000000` (sentinel; derived bit 0 = 1) | `jo` taken | suppressed |
| `0` | `jae` taken | suppressed |
| any other value (register record with a live first qword) | neither | fires |

Combined with the scratch-name-pair result: for the two scratch names
the flag byte is 0, so the derived byte is odd for every input byte and
both field blocks always select the sentinel record — its drop is
always suppressed. For the other 77 names the derived byte equals the
input byte at `+0x4d`, so its bit 0 makes this choice per record. On
the `rsi == 0` regime there is no guard at all: either record variant
is copied verbatim to the output.

Reproduce from the repository root:

```bash
python3 -B tools/derived_byte_callee_static.py
python3 -m unittest tests.test_derived_byte_callee_static -v
```

Callee behaviour for the derived-byte-selected record only: the entry
split on the `rsi` argument (zero copies the record to the output,
nonzero builds the output and drops the record under the pinned
guard), the consumer-side selection of that record by bit 0 of the
derived byte at its two field blocks, and the four direct call sites.
What the two calls through slot `0x64df6e8` compute with the flag-group
pointer, what the pair and the constructed record fields mean, and the
record contents beyond the first qword's guard role are NOT
established by these bytes. The flag and derived bytes' construction
is owned by the RE-015 scratch-name-pair packet and is cited here, not
re-derived. The next question is what slot target `0x141e3a0` does
with the flag-group pointer it receives twice through this callee.
No captured code executed, no runtime value, indirect-call recovery,
#94 correspondence, or reconstruction gate is claimed.
