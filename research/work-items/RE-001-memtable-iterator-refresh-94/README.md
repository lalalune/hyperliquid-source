# RE-001: map node #94 MemtableIterator refresh handler family (0x5167ba0, 0x5167cf0, 0x5167e40, 0x5167fd0, 0x51684d0)

Task: RE-001 (#94 function map). Bounded question: how do the five node #94
routines that refresh a MemtableIterator decide whether to refresh, what
record do they install, and when do they report — and how do the five
variants differ?

- Component: node #94 MemtableIterator refresh handler family. Five windows,
  all extracted from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5167ba0..0x5167ce7` (327 bytes, FDE 0xf7d104),
  `0x5167cf0..0x5167e37` (327 bytes, FDE 0xf7d13c),
  `0x5167e40..0x5167fc7` (391 bytes, FDE 0xf7d174),
  `0x5167fd0..0x5168157` (391 bytes, FDE 0xf7d1ac),
  `0x51684d0..0x5168604` (308 bytes, FDE 0xf7d25c), plus the known
  predicate `0x51647b0..0x51647c4` (20 bytes, FDE 0xf7caac). The reader
  `0x5167040` and the report routine `0x522e770` are used by contract only.
- Claim status: observation for the window bounds, the guard order, the
  install order, the free-after-install order, the report trigger and
  registers, the predicate rule, the perf prologue steps, the census and
  the relocation slots; inference for the names "MemtableIterator",
  "refresh handler", "ready", "tag width" and "record" (the report format
  string literally names MemtableIterator and `db/memtable.cc`; the other
  names describe the observed field roles); unresolved for the iterator
  subclass names, the member object type behind field `+0x50`, the
  first-virtual roles, the reader tag/hash internals, and the report
  routine's own logging semantics beyond its observed call registers.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at each window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers these
  windows (checked this cycle: 66 open, no 0x5167ba0/0x5167cf0/
  0x5167e40/0x5167fd0/0x51684d0 title). The neighbouring WAL windows
  (#1969, #1966, #1964, #1958, #1948, #1982) map different functions.
  The reader `0x5167040` itself is NOT mapped here — its tag/hash
  internals, error strings and integer-format path are a separate,
  larger work item — only its handler-visible contract is recorded.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in AGENTS.md
  is therefore unavailable and this packet is grounded in objdump
  disassembly plus relocation and FDE records only. pytest is not
  installed, so the pytest-style test file runs under plain python3
  via its `__main__` runner.

## Answer

`refresh(iterator)` returns void. The iterator layout below lists only
fields the windows read or write.

Iterator layout:

- `+0x00`: vtable pointer; its `+0x10` slot holds the predicate virtual.
- `+0x50`: member object pointer; its `+0x10` virtual returns the ready
  byte and its `+0x18` virtual returns the buffer for the reader.
- `+0x58`: ready byte. Variants ba0/cf0/e40/fd0 write it from the
  `+0x10` virtual result; variant 84d0 reads it as a stored field.
- `+0x60`: tag width passed to the reader. Zero returns without a refresh.
- `+0x68`: installed record code (u32). The clear gate and the report
  trigger both read it.
- `+0x6c`: installed record subfield (u16).
- `+0x70`: installed record detail pointer; the old value is freed
  after the install.
- `+0x78`: report context passed to the report routine.

Variants (identical core; only the head differs):

| variant | window | first virtual on `+0x50` | perf prologue | ready source |
| --- | --- | --- | --- | --- |
| ba0 | 0x5167ba0 | `+0x48` | none | `+0x10` virtual |
| cf0 | 0x5167cf0 | `+0x50` | none | `+0x10` virtual |
| e40 | 0x5167e40 | `+0x28` | counter at TLS `+0x150` | `+0x10` virtual |
| fd0 | 0x5167fd0 | `+0x20` | counter at TLS `+0x148` | `+0x10` virtual |
| 84d0 | 0x51684d0 | none | none | stored field `+0x58` |

Flow, in order:

1. Perf variants (e40/fd0) only: if the global slot `0x5777ef8` is
   nonzero, call the thread-local getter (PLT `0x56606a0`) and discard
   its result; read the thread-local byte at fs:0 minus `0x10a8`; if
   it is at most 1, skip the rest; otherwise call `0x52cd6e0` (role by
   contract) and increment the thread-local counter (e40 `+0x150`,
   fd0 `+0x148` above the TLS base at fs:0 minus `0x350`).
2. Variants ba0/cf0/e40/fd0 only: call the first virtual on the
   `+0x50` object (its result is ignored), then its `+0x10` virtual,
   and store the low byte to `+0x58`. Variant 84d0 skips both calls.
3. If `+0x60` is zero, return. For ba0/cf0/e40/fd0 the ready byte has
   already been stored at this point.
4. Load the outer vtable `+0x10` slot value.
   - Known-predicate case (slot value equals `0x51647b0`): return if
     `+0x58` is zero; return if `+0x68` is nonzero.
   - Other-predicate case: call the slot virtual on the iterator;
     return if it returns zero; reload `+0x60` and skip the inline
     ready and clear checks.
5. Call the `+0x50` object `+0x18` virtual to obtain the buffer.
6. Call the reader `0x5167040` with (stack record, buffer, `+0x60`, 0).
7. Install: `+0x68` from the record code, `+0x6c` from the record
   subfield, `+0x70` from the record detail; the stack record fields
   are zeroed as moved-from.
8. Free the old `+0x70` value with array delete if it is non-null.
   This free happens AFTER the install, so if the new detail equals
   the old pointer, the installed pointer is freed by the same step.
   The second array delete in each window targets the already-zeroed
   moved-from record pointer, so it never fires.
9. If the installed `+0x68` is nonzero, tail-call the report routine
   `0x522e770` with level 3, context `+0x78`, format
   `[%s:538] In MemtableIterator: %s`, file `db/memtable.cc`, and
   detail `+0x70`. Otherwise return normally.

Known predicate `0x51647b0` (20 bytes): returns true exactly when
`+0x58` is nonzero and `+0x68` is zero — that is, ready and not
already installed. The known-predicate case above is the inline
duplicate of this rule; the other-predicate case delegates to the
iterator subclass's own predicate, whose rule is not pinned here.

Reader contract (by contract only): the handler always passes mode 0.
A matching tag yields an all-zero record, which installs code 0 and
triggers no report; a tag mismatch or parse failure yields a filled
record, which installs a nonzero code and triggers the report. The
reader's tag/hash internals are not claimed here.

Census (per-byte 0xe8/0xe9 scan of .text plus .rela.dyn parse):

- ba0/cf0/e40/fd0/predicate: 0 direct calls, 0 tail jumps; reached
  only through R_X86_64_RELATIVE slots — ba0 `0x575b248`, cf0
  `0x575b250` and `0x5778418`, fd0 `0x575b268` and `0x5778428`,
  e40 `0x575b278` and `0x5778420`, predicate `0x575b240` and
  `0x57783d0` (the slot the handler compares against).
- 84d0: 3 direct calls, 0 tail jumps — `0x516888f` (inside
  `0x5168610`), `0x5168c3f` and `0x5168d29` (both inside `0x5168a20`);
  no RELATIVE slot.
- Reader `0x5167040`: 8 direct calls, 0 tail jumps — the five
  in-scope sites above plus `0x516833f` (inside `0x5168160`),
  `0x5168ef5` (inside `0x5168a20`) and `0x516b2ba` (inside
  `0x516b130`). The three out-of-scope callers are not claimed here;
  their bodies differ in prologue and arguments and need their own
  analysis.
- Report `0x522e770`: 341 direct calls, 10 tail jumps across the
  binary (a shared logging routine); the five in-scope tail sites are
  `0x5167cac`, `0x5167dfc`, `0x5167f8d`, `0x516811d` and `0x51685c7`.
