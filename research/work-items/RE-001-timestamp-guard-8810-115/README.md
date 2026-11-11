# RE-001: node #115 timestamp guard 0x5d58810

## Bounded question

What does routine `0x5d58810` (FDE `0x5d58810..0x5d58ac5`,
693 bytes) do when a caller asks whether a method may run on a
column family: when does it return an empty OK status, and what
message does it build when the column family enables
timestamps?

## Answer, pinned to the target

The routine takes three arguments — an out Status pointer in
`rdi`, a factory pointer in `rsi`, and an object pointer in
`rdx` — and returns the out Status. End to end, in order:

1. **Resolve.** When the object (`rdx`) is non-null it is used
   as-is and the factory is never read. When it is null, the
   factory vtable slot `0x3e8` is read: when the slot equals the
   default getter `0x5d48510` (`mov 0x740(%rdi),%rax; ret`),
   the object is `*(factory+0x740)` (the load is inlined);
   otherwise the slot is called with the factory and its return
   is the object.
2. **Describe.** The virtual method at vtable slot `0x28` of
   the object is called; its result `P` is read at `+0x28`.
3. **Gate.** When `P+0x28` is null the routine writes an empty
   OK status (code 0, subcode 0, no message) and returns. No
   message is built and the name slot is never called.
4. **Name.** The virtual method at vtable slot `0x10` of the
   object is called; it returns a pointer to a `{ptr:+0,
   len:+8}` view.
5. **Message.** An `ostringstream` assembles
   `"cannot call this method on column family "` + name +
   `" that enables timestamp"`, copied into a temp string.
6. **Build.** Helper `0x61cf670` writes the status: code `4`
   (InvalidArgument), subcode `0`, message pointer at `+0x08`
   to a new heap buffer holding the first view, plus `": "` and
   the second view only when the second view is non-empty; the
   old message buffer is freed with `delete[]` when non-null.
   The second view here is `{ptr 0x4376fd, len 0}`: the byte at
   `0x4376fd` is `0x00` and the oneshot.rs path text that
   follows at `+1` is never copied, so the message is exactly
   the first view.

The routine's own control transfers are 15 direct calls (the
ostringstream constructor, three `__ostream_insert` calls, the
string `_M_replace`, the status builder, three `_M_dispose`
calls, the locale and `ios_base` destructors, `_M_assign`,
the ostringstream destructor, `__stack_chk_fail` and
`_Unwind_Resume`), 3 indirect calls (the describe slot, the
name slot and the resolve slot), and no tail jumps. Its three
landing-pad entries at `0x5d58aa5`, `0x5d58aae` and `0x5d58ab4`
lie inside the FDE range and dispose the temp string and/or
the ostringstream before resuming unwinding; they are
recorded, not modelled as normal returns. The builder's
cleanup block at `0x61cf650..0x61cf65e` frees the old message
buffer with `delete[]` when non-null and resumes unwinding,
followed by `int3` padding to `0x61cf670`; it is reached from
the builder landing-pad entry at `0x61cf75b`.

## Consumers (site windows)

The census finds exactly 15 direct call sites, no tail jumps.
Argument setup observed at the sites:

- Six sibling callers in `0x5e94540..0x5e95ef7` forward their
  incoming `rcx` as the object and use a stack-temp out
  (`rsp+0x10`; one uses `rsp`).
- Two callers (sites `0x5d6db9a`, `0x5d78f08`) reach the guard
  only on the `*(rax+0x58) == null` path, passing the indexed
  element as the object and a stack slot as the factory (the
  non-null branch jumps elsewhere and does not call the guard).
- Three callers (sites `0x5d60c49`, `0x5e71749`, `0x5e7dc39`)
  pass a stack-slot factory, a saved-register object and a
  saved-register out.

Only the site windows are claimed; each caller's wider
semantics are not pinned here. The full site list with caller
FDE ranges is in `callers.tsv`.

## Status layout

The out status is 16 bytes: code at `+0x00`, subcode at
`+0x01`, a byte from the builder's sixth argument at `+0x02`
(`0` here), zeroes at `+0x03..0x05`, message pointer at
`+0x08`. Bytes `+0x06..0x07` are never written by either path.
The OK path zeroes `+0x00..0x05` and `+0x08..0x0f`. The
message buffer is a plain NUL-terminated heap string of
`len1 + (len2 ? 2 + len2 : 0)` bytes; no length prefix is
stored.

## NOT claimed

What the describe result `P` or its `+0x28` field denote, what
the factory's `+0x740` object or the passed object denote,
which concrete column-family names occur at runtime, caller
semantics beyond the site windows above, or behaviour on
dangling pointers, a null describe result, or a null object
pointer (the routine reads the object vtable
unconditionally, so the model raises on a null object).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole guard, verbatim, produced by
  `objdump -d --start-address=0x5d58810 --stop-address=0x5d58ac5 work/hl-node-115.bin`.
  `status_builder.txt`: the whole builder, verbatim
  (`0x61cf670..0x61cf767`). `default_getter.txt`: the whole
  getter, verbatim (`0x5d48510..0x5d4851c`). Instruction-level
  detail lives only in these excerpt texts, not in
  `records.json`, which carries semantic records only.
  Mnemonics in the excerpts (including `endbr64` at each
  routine entry and at the landing-pad entries) are genuine
  instructions present in the target binary, not placeholders;
  `verify.py` checks every excerpt instruction byte-for-byte
  against the raw binary and against a fresh objdump run.
- `frames.txt`: the three routine FDE lines plus every
  distinct caller FDE line, from
  `readelf --debug-dump=frames`.
- `callers.tsv`: all 862 direct call sites (15 guard, 847
  builder, 0 getter) with caller FDE ranges, reproduced by
  `census.py`.
- `relocations.txt`: the 4 `R_X86_64_RELATIVE` records naming
  the getter address as an addend, applied at `.data.rel.ro`
  offsets `0x64c9750`, `0x64cb4c8`, `0x64cb9a8`, `0x64cbfa8`
  (vtable slots); the same four values are the stored qwords
  the raw scan finds in `.rela.dyn`. The guard and builder
  addresses have no RELATIVE record.
- `records.json`: semantic records only (resolve rule, gate,
  name view, message literals, builder contract, census
  counts, caller patterns).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-timestamp-guard-8810-115/export_excerpts.py`
- `python3 research/work-items/RE-001-timestamp-guard-8810-115/census.py`
- `python3 research/work-items/RE-001-timestamp-guard-8810-115/verify.py`
- `python3 tests/test_timestamp_guard_8810_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
model tests are claimed.

## Next step

The six sibling callers in `0x5e94540..0x5e95ef7` share one
prologue shape; pinning what those six methods do around the
guard (and what object their incoming `rcx` is) is the natural
follow-up. The builder `0x61cf670` is the shared Status
constructor used at 847 sites; its other callers' code/subcode
pairs would show which statuses the node builds.
