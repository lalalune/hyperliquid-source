# RE-001: pin node #115's Find delegate vtable family

Bounded question: what is node #115's Find delegate vtable family —
which vtable does each delegate class use, what does each
delegate-interface slot (0x10..0x98) do, and how does find_entry
dispatch through the delegate?

This closes the explicit open unknown from #3485's README: "The
delegate vtable base address: the delegate's vtable slots
0x70/0x78/0x80/0x90 and the node+0x28 vtable slots 0x40/0x78 need a
base, which was not pinned from locally retained evidence."

## Answer, end to end

The delegate is the Customizable object find_entry (0x609e510)
dispatches through. Its vtable sits at the matcher node's +0x28
object pointer: the create host 0x6077820 passes *(rbp) — its 4th
argument (rcx), a shared_ptr<Statistics> holder whose +0x00 is the
Statistics* — as find_entry's delegate. StatisticsImpl is the only
delegate class whose slot 0x88 reads +0x28, matching the matcher
node's +0x28 delegate pointer.

### How the family was derived

The binary's own relocation table pins the family; nothing below
is trusted from a hand-written list. The derivation (implemented in
gen_records.py, reproducible from the binary alone):

* A typeinfo object at T has a type-1 reloc (R_X86_64_64) at T with
  symbol 260 (_ZTVN10__cxxabiv117__class_type_infoE) or 261
  (_ZTVN10__cxxabiv120__si_class_type_infoE). The name is the C
  string at the RELATIVE target of the +0x08 slot; the base class is
  the RELATIVE target of the +0x10 slot (single-inheritance
  typeinfos only). **701 typeinfo objects.**
* A strict vtable at base B has a RELATIVE reloc at B−0x8 whose
  addend is a typeinfo, with no reloc at B−0x10 (the offset-to-top
  slot). **406 strict vtables.**
* A table's slots run from its base while each slot is a RELATIVE
  reloc into .text (a concrete function), a type-1 reloc with
  symbol 263 (__cxa_pure_virtual, addend 0), or a NULL slot (no
  reloc, file content 0); the table ends at the first slot that is
  none of those, capped by the next strict vtable's base minus
  0x10.

Vtable layout convention (empirically consistent across all 406
strict vtables, including StatisticsImpl 0x64d2d88): the vtable base
B has B−0x8 = the typeinfo pointer and B−0x10 = 0 (offset-to-top);
slots sit at B+offset exactly as the call sites use them. Note:
#3563's "vtable 0x64d31b0" is 8 less than this convention's base
(0x64d31b8) for ConfigurableCFOptions; this packet uses the
compiler convention (vptr + displacement) and says so explicitly.

### The 19-table family

| vtable | class | slots | install sites (lea) |
|---|---|---|---|
| 0x64cda68 | EnvLogger | 11 | 0 |
| 0x64cdad0 | Env | 85 | 0 |
| 0x64cdd88 | SystemClockWrapper | 26 | 0 |
| 0x64ce2d8 | CompositeEnv | 85 | 0 |
| 0x64ce590 | CompositeEnvWrapper | 85 | 0 |
| 0x64ce930 | PosixClock | 26 | 1 |
| 0x64cea10 | PosixEnv | 85 | 3 |
| 0x64d1398 | MockEnv | 85 | 0 |
| 0x64d1650 | EmulatedSystemClock | 26 | 0 |
| 0x64d1940 | MockEnvDirectory | 6 | 1 |
| 0x64d1980 | MockEnvFileLock | 2 | 3 |
| 0x64d19a0 | TestMemLogger | 11 | 4 |
| 0x64d1f00 | AutoRollLogger | 11 | 0 |
| 0x64d2d88 | StatisticsImpl | 32 | 0 |
| 0x64d3138 | ConfigurableMutableCFOptions | 14 | 0 |
| 0x64d31b8 | ConfigurableCFOptions | 14 | 0 |
| 0x64d3430 | Configurable | 14 | 0 |
| 0x64d3638 | MutableDBConfigurable | 14 | 0 |
| 0x64d36b8 | DBOptionsConfigurable | 14 | 0 |

The full slot map for every table is in vtables.tsv (646 rows);
records.json carries the same data plus the slot contracts below.

### Two structural facts

* Env, StatisticsImpl, SystemClockWrapper and the wrapper classes
  share slots 0x10..0x68, 0x78, 0x80, 0x90; they differ at 0x00/0x08
  (destructors — abstract classes have NULL slots 0x00/0x08, concrete
  classes have real functions), 0x70 (Name), 0x88 (wrapped object)
  and 0x98+.
* Configurable (14 slots, 0x00..0x68) and Logger (11 slots) have NO
  identity slots 0x70+. So a find_entry delegate is an Env /
  Statistics / SystemClock-family Customizable, never a Configurable
  or a Logger.

### Install sites: most delegate objects are not built here

Only 6 of the 19 classes have a `lea` install site anywhere in this
binary's .text (PosixEnv 3, PosixClock 1, TestMemLogger 4,
MockEnvDirectory 1, MockEnvFileLock 3; PosixFileSystem 5 more, but
FileSystem is a different hierarchy and is a census target only).
The other 15 vtable bases never appear as an instruction operand
and no relocation holds them as a value. Their objects are not
constructed by any code in this binary, so the delegate objects
find_entry actually dispatches on arrive through construction paths
outside this binary's .text. That is recorded as an open unknown,
not smoothed over.

The census (callers.tsv, 75 rows) also shows most slot
implementations are reachable only through the vtable: the unwrap
function pointer 0x5d4d490 is stored in 29 places (the most of any
target), while most shared slot functions have 0 direct calls.

### The delegate interface, slot by slot (0x10..0x98)

* **0x10 GetOption** (shared 0x609d760): if the option name is
  exactly "id" (length 2, bytes 0x6469), return the delegate's own
  name (its slot-0x78 string) and a zeroed Status; otherwise forward
  to Configurable's slot 0x10 (0x6099030), which resolves the name
  through the delegate's slot 0x68 and calls worker 0x6098ad0.
* **0x18 ConfigureOption** (shared 0x609dc40): return 1 when the
  value's +0x2c byte is <= 1 or out == delegate; return 0 when the
  delegate is null. Otherwise compare the delegate's name with this
  object's name through slot 0x78; on a mismatch rewrite the option
  name to "id" (0x441b15), then forward to Configurable's slot 0x18
  (0x60996a0) when +0x2c > 2, else return 1.
* **0x20 init** (0x5d32560): initialize a std::string at rdi
  (pointer rdi+0x10, length 0, NUL at +0x10).
* **0x28 parse/apply records** (shared 0x6095e70, 1964 B): walk
  0x30-byte records; per record copy the name (SSO-aware) and the
  0x20-byte value struct, then walk its +0x18 entry chain;
  materialize five sub-values through the +0x40/+0x60/+0x80/+0xa0/
  +0xc0 copy function pointers (tag 2). The worker 0x60b9e00 fires
  when (HIGH dword of the entry's +0xd0 qword − 4) > 1 (unsigned;
  a high dword of 0..3 wraps and also passes) and the 0x40 bit of
  the byte at +0xd9 is clear and (the materialized +0xa0
  sub-value's first qword is non-null or (LOW dword of the +0xd0
  qword − 0x15) ≤ 1 unsigned). When +0xc0 is null the binary skips
  materializing that sub-value and jumps to a second, identical
  gate site. SystemClockWrapper's override (0x5fcf590) lazily
  creates the wrapped PosixClock through 0x5fe2680 into +0x20 when
  it is null, then runs the shared worker. MockEnv's override
  (0x5fd7560, shared with CompositeEnvWrapper) lazily creates the
  wrapped PosixEnv (+0x48) through 0x5fe2860, +0x28 through
  0x5fcf390, and +0x38 through 0x5fcf430, then runs the shared
  worker.
* **0x30 parse/apply records, worker 2** (shared 0x6096790, 1916 B):
  same record walk; the worker 0x60b9f50 (six arguments) fires when
  (HIGH dword of the +0xd0 qword − 4) > 1 unsigned and (the raw
  +0xc0 function pointer is non-null or (LOW dword of the +0xd0
  qword − 0x15) ≤ 1 unsigned). No 0x40 flag check.
* **0x38 resolve name** (shared 0x5d2e090): the shared resolver
  0x60958c0 scans the 0x30-byte (name, +0x20 field) record array at
  *(rdi+0x08)..*(rdi+0x10) for the name in rsi (length then memcmp,
  SSO-aware) and returns the matching record's +0x20 field, or
  null. Otherwise call this object's slot 0x88 (the wrapped
  object) and, when non-null, tail-jump to the wrapped object's
  slot 0x38. ConfigurableCFOptions' override (0x607dd50) compares
  the name against the .bss string at 0x6506ac0 and returns
  this+0x330 on a match; DBOptionsConfigurable's override
  (0x60a0240) compares against the .bss string at 0x6506d60 and
  returns this+0x2d8 (the start of the DBOptions snapshot block
  that slot 0x48 copies into).
* **0x40 zero Status** (0x60956f0): write a zeroed 16-byte Status
  into *(rdi) and return rdi. Byte-identical copies at 0x5fcc0e0
  and 0x5fcc100.
* **0x48 merge host** (shared 0x609d0e0; see #3560): the overrides
  call host A first and return early when its Status is non-zero,
  then call the delegate's slot 0x28 and copy its Status out.
  ConfigurableMutableCFOptions (0x607e420) additionally calls
  0x60c0580 and 0x60c2a10; DBOptionsConfigurable (0x60a2470, 3361 B)
  reads the DBOptions snapshot through 0x60c2e20 and copies it
  field-by-field into this+0x2d8..+0x560, then calls finalize helper
  0x5d354b0.
* **0x50 SetOption** (shared 0x60986b0): when the value kind byte
  (+0x04) is 0, forward (name, value) to worker 0x60bedc0. When
  kind != 0 and the changeable flag at name+0xb1 is set, copy the
  value struct (shared_ptr refcounted) and call 0x60bedc0. When
  kind != 0 and the flag is clear, build "Option not changeable: "
  (0x4341c2) + name and report it through 0x61cf670 with code 4.
  Always returns the out Status. TestMemLogger's slot 0x50
  (0x5fcc480) returns Status code 3 (kNotSupported shape).
* **0x58 validate** (shared 0x6095710): call kind validator
  0x60bf980; if it accepts, return 1. Otherwise call 0x60bf7c0; if
  it rejects too, blank the target name (replace with ""). Always
  returns 1. The twins 0x6086b70/0x60a7420 (re-shipped from #3563)
  are byte-identical after address normalization except the
  holder-map loads (0x630 in A, 0x90 in B).
* **0x60 serialize** (shared 0x609de80): call the delegate's slot
  0x78 for its name; when the value kind (+0x28) is 1 or the
  delegate name is empty, compose the out string as <options name>
  + "id" + "=" + <delegate name> + <value name>; otherwise forward
  to Configurable's slot 0x60 (0x60985e0). SystemClockWrapper's
  override (0x5fcdae0) appends "target=" + the wrapped clock's
  serialization when the wrapped clock is a non-default clock
  (its slot 0x80 must be the canonical IsInstanceOf and its
  Name()/NickName() must not be "DefaultClock"). MockEnv's override
  (0x5fd5e00) appends "target=" + the wrapped env's serialization
  when the wrapped PosixEnv differs from the default.
* **0x68 dotted-name** (shared 0x609d980): call the delegate's slot
  0x70 (Name()); if the input name starts with Name() + '.', strip
  the prefix and return the remainder; if Name() is null, throw
  std::logic_error; otherwise fall back to Configurable's slot 0x68
  (0x6095a60), a std::string copy.
* **0x70 Name()**: "" for Env/CompositeEnv (0x5fcc0d0),
  "BasicStatistics" for StatisticsImpl (0x606fa20, 0x432248),
  "CompositeEnv" for CompositeEnvWrapper (0x5fd4e60, 0x43e762),
  "DefaultClock" for PosixClock (0x5fe0fe0, 0x431007), "PosixEnv"
  for PosixEnv (0x5fe1000, 0x438375), "MockEnv" for MockEnv
  (0x6025790, 0x447686), "TimeEmulatedSystemClock" for
  EmulatedSystemClock (0x60257a0, 0x4372ae). SystemClockWrapper's
  slot 0x70 is NULL (pure virtual): calling Name() on it would
  crash; the binary never does.
* **0x78 name as std::string** (0x5d32a30, shared by all nine
  interface classes): call the delegate's slot 0x70 (Name()) and
  assign the returned C string into the sret std::string through
  0x5d32940.
* **0x80 IsInstanceOf** (canonical 0x5d2e770): return 1 when the
  input matches Name() (slot 0x70) or NickName() (slot 0x90) by
  length then memcmp, else 0. MockEnv and CompositeEnvWrapper
  override it (0x5fd6240): return 1 when the input is exactly
  "CompositeEnv" (length 12), else tail-jump to the canonical.
* **0x88 wrapped/parent object**: Env returns 0 (0x5d2ca00);
  SystemClockWrapper returns *(obj+0x20) (0x5fcc3f0); MockEnv and
  CompositeEnvWrapper return *(obj+0x48) (0x5fd4e70);
  StatisticsImpl returns *(obj+0x28) (0x606fa30).
* **0x90 NickName()**: "" for Env (0x5d2ca10), "PosixClock" for
  PosixClock (0x5fe0ff0, 0x44768e), "DefaultEnv" for PosixEnv
  (0x5fe1010, 0x431014).
* **0x98 unwrap/status/time**: Env (0x5fcc0e0) writes a zeroed
  Status. CompositeEnv/PosixEnv/MockEnv (0x5fd5a00) take the object
  at the 2nd argument's +0x28; when its slot-0x98 is the terminal
  stub 0x5fcc240 (GOT 0x64ed8b0) they write a zeroed Status, else
  they call that slot-0x98. SystemClockWrapper (0x5d4d490) walks
  the +0x20 chain, comparing each level's slot-0x98 against the GOT
  slot 0x64ecf80 (0x5d4d490 itself), 10 levels unrolled, then
  tail-jumps to the innermost slot-0x98. PosixClock (0x5fe1540)
  calls gettimeofday and returns tv_sec * 1,000,000 + tv_usec
  (microseconds since the epoch). EmulatedSystemClock (0x60259e0)
  returns (flag at +0x48 clear ? the wrapped clock's (+0x20)
  slot-0x98 : 0) + the offset at +0x40. StatisticsImpl (0x6070490)
  runs the +0x38 field's pre-hook 0x60d5230, calls core 0x6070430,
  runs the post-hook 0x60d52f0, and returns the core result.

Logger-family slots (0x5fcc410 one-shot gate at slot 0x10,
TestMemLogger slot 0x30 0x6025980, TestMemLogger slot 0x50
0x5fcc480) are excerpted for comparison but their remaining method
bodies belong to the Logger/Directory interfaces, not the
Customizable delegate interface, and are not given contracts here.
The 85-slot Env-family tables have Env-specific slots at 0xa0..0x2a0
outside the delegate interface; they are listed in vtables.tsv but
not given contracts here.

### find_entry's delegate dispatch

find_entry (0x609e510) calls the delegate through four sites:
`call *0x78(%rax)` at 0x609e5a1 (name as std::string),
`mov 0x80(%rax),%rdx; cmp GOT 0x64eceb8` at 0x609e644 (the
delegate's IsInstanceOf must be the canonical 0x5d2e770 — MockEnv
and CompositeEnvWrapper fail this check, since their slot 0x80 is
0x5fd6240), `call *0x70(%rax)` at 0x609e666 (Name()),
`call *0x90(%rax)` at 0x609e68a (NickName()). delegate_impl
(0x6097110) calls the delegate's slot 0x48 (merge host) at
0x609712d.

### The 80-byte option value struct

From #3485: +0x00 u32, +0x04 u8 (kind byte, slot-0x50 dispatch),
+0x08 std::string, **+0x28 u32 (kind, slot-0x28/0x30/0x60 gates)**,
+0x2c u8 (flags, slot-0x18 gate), +0x30 u64, +0x38 16 B, +0x48
shared_ptr control. Keep this apart from the matcher node's +0x28
object pointer (the delegate): #3485's "+0x28 delegate" open
unknown is the matcher node's +0x28, not this struct's +0x28 kind
field. MockEnv's slot 0x28 partially answers which construction
paths install a non-null +0x28 delegate (lazy creation through
0x5fcf390/0x5fcf430/0x5fe2860); the creator bodies are not in this
packet.

### GOT landmarks

| GOT slot | target | meaning |
|---|---|---|
| 0x64eceb8 | 0x5d2e770 | canonical IsInstanceOf (slot 0x80) |
| 0x64eceb0 | 0x5d2ca10 | canonical NickName (slot 0x90, Env "") |
| 0x64ecf50 | 0x5d48960 | forwarder |
| 0x64ecf80 | 0x5d4d490 | unwrap (slot 0x98, SCW) |
| 0x64ed8b0 | 0x5fcc240 | terminal slot-0x98 stub (zeroed Status) |

### Evidence

* `excerpts/` — 55 whole-function objdump excerpts, verbatim as
  objdump emitted them (command: `objdump -d
  --start-address=0x<start> --stop-address=0x<stop>
  work/hl-node-115.bin`; the windows are listed in
  export_excerpts.py). Mnemonics such as `endbr64` are genuine
  instructions present in the target binary, not placeholders.
  Re-shipped byte-identical from earlier packets, credited in
  records.json: slot48_host_a (#3560), twin_a/twin_b (#3563),
  delegate_impl (#3485).
* `records.json` — semantic records only (no per-instruction
  mnemonic list): the 19-table family with slot maps, the 18
  interface-slot contracts, find_entry dispatch sites, GOT
  landmarks, literals, census counts, open unknowns.
* `vtables.tsv` — one row per family slot (646 rows).
* `callers.tsv` — the census: every call/jmp/lea site in .text
  that targets a packet routine or a family vtable base (75 rows),
  produced by census.py (streaming objdump; /tmp is a 512 MB tmpfs
  and a full objdump dump does not fit there).
* `frames.txt` — the FDE lines for all 55 excerpt windows
  (gen_frames_relocs.py).
* `relocations.txt` — the readelf rows pinning the family: every
  slot reloc of the 19 tables, the typeinfo-object relocs, and the
  five GOT landmark rows (gen_frames_relocs.py).
* `census.py`, `export_excerpts.py`, `gen_records.py`,
  `gen_frames_relocs.py` — the generators, committed in the packet.
* `verify.py` — the independent checker; run it from the repo root
  (`python3 research/work-items/RE-001-delegate-vtable-115/verify.py`).
  It checks the artifact digest, MANIFEST coverage, excerpt
  regeneration, raw bytes, three seeded random gate spots, FDE
  presence, relocations, literals, census reproduction, model
  constants (family re-derived from the relocations, GOT landmarks,
  twin byte-identity, parse-gate constants), and the model tests.
* `tools/delegate_vtable_115.py` + `tests/test_delegate_vtable_115.py`
  — the Python model of the family (Name/NickName/IsInstanceOf,
  wrapped-object offsets, the resolver scan, the slot-0x18/0x50/
  0x58/0x60 guards, the parse gates, the clock slot-0x98
  arithmetic, the unwrap chain) and 34 tests that exercise
  dispatch outcomes end to end.

Artifact: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json).

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` cannot run here;
the packet's own verify.py and the model tests are the checks that
did run. The binary work/hl-node-115.bin is the materialized node
#115 binary whose hash matches provenance/artifacts.json.

## Open unknowns

* Which construction paths install a non-null +0x28 delegate on the
  matcher node: MockEnv's slot 0x28 lazily creates +0x28 via
  0x5fcf390 and +0x38 via 0x5fcf430, and SCW's slot 0x28 lazily
  creates its wrapped PosixClock via 0x5fe2680, but the creators'
  bodies (0x5fcf390, 0x5fcf430, 0x5fe2680, 0x5fe2860) are not in
  this packet.
* SystemClockWrapper's slot 0x70 (Name) is NULL: calling Name() on
  a SystemClockWrapper would crash; the binary never does
  (find_entry calls slot 0x78 on the delegate, which calls slot
  0x70 only on the wrapped object).
* The Configurable configure worker's callee 0x6099100 (tail-jumped
  to by conf_slot18) is not in this packet.
* The slot-0x58 kind validators 0x60bf980 and 0x60bf7c0 are not in
  this packet.
* The slot-0x28/0x30 workers 0x60b9e00 and 0x60b9f50, the slot-0x50
  worker 0x60bedc0 and reporter 0x61cf670, the slot-0x60 worker
  0x6097630, the Configurable slot-0x10 worker 0x6098ad0, and the
  slot-0x60 append helpers 0x5fcd890/0x5fcd6f0/0x61d13e0/0x61d1390/
  0x60971c0/0x5fd5cc0 are not in this packet.
* StatisticsImpl's +0x28 field (read by its slot 0x88) and the .bss
  strings at 0x6506ac0 (ConfigurableCFOptions slot 0x38) and
  0x6506d60 (DBOptionsConfigurable slot 0x38) are runtime-built;
  their values are not recoverable from the static binary.
* The Logger-family method bodies (EnvLogger/AutoRollLogger slots
  0x18..0x50, TestMemLogger slots 0x18/0x20/0x38, MockEnvDirectory
  slots 0x10/0x18/0x28) belong to the Logger/Directory interfaces,
  not the Customizable delegate interface, and are not excerpted
  here.
* The 85-slot Env-family tables have Env-specific slots at
  0xa0..0x2a0 outside the delegate interface; they are listed in
  vtables.tsv but not given contracts here.
* find_entry's branch outcome when the delegate's slot 0x80 is not
  the canonical IsInstanceOf (MockEnv/CompositeEnvWrapper) is not
  pinned here; only the comparison site (0x609e644) is.

## Cross-references

* #3378 — DB-family vtables (0x64c9368, 0x64cb0e0, 0x64cb5c0,
  0x64cbbc0) and the StatisticsImpl table (0x64d2d88, 32 slots)
  were pinned there; this packet re-ships only the StatisticsImpl
  delegate-interface comparison rows and credits #3378. Its records
  mention 0x64c9120 (rocksdb::DB typeinfo, not a vtable) and
  0x64d2cf8/0x64d2d88 (StatisticsImpl typeinfo/vtable).
* #3362 — StatisticsImpl vtable (0x64d2d88) pinned there; credited
  here for the table base.
* #3485 — Registry Find: find_entry (0x609e510), find_norm, the
  matcher, delegate_impl (0x6097110, re-shipped here), and the value
  struct layout.
* #3488 — Sibling entry point and the '=' helper (slot-0x40
  zero-status stub).
* #3560 — Find-family merge: host A (0x609d0e0, re-shipped here).
* #3563 — Default name: the twin slot-0x58 entries (0x6086b70/
  0x60a7420, re-shipped here) and the StatisticsImpl Name() literal
  "BasicStatistics". Its "vtable 0x64d31b0" is 8 less than this
  packet's convention base 0x64d31b8; see the layout note above.
