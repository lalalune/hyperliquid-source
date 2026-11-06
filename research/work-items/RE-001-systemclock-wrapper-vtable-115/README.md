# RE-001: pin node #115 SystemClockWrapper vtable slots — what each of the 26 slots implements

Bounded question: which function does each slot of the
`SystemClockWrapper` vtable implement, and how does the wrapper
dispatch time calls through its wrapped clock?

Resolves the open unknown left by open PR #3352 ("Which of the
wrapper vtable's other slot functions each implement").

## Answer

The wrapper vtable (stored pointer `0x64cdd88`, Itanium base
`0x64cdd78`, typeinfo `N7rocksdb18SystemClockWrapperE` at `0x64cd960`)
has 26 slots. Slots 0, 1 and 14 are **null** (no
`R_X86_64_RELATIVE` record covers them); the other 23 are:

| Slot | Function | Identity |
|---|---|---|
| 2 | `0x609d760` | `Customizable::GetOption` (98.00% vendor census) |
| 3 | `0x609dc40` | `Customizable::AreEquivalent` (93.47%) |
| 4 | `0x5d32560` | returns empty `std::string` (C++ name open) |
| 5 | `0x5fcf590` | `SystemClockWrapper::PrepareOptions` (92.00%) |
| 6 | `0x6096790` | `Configurable::ValidateOptions` (96.45%) |
| 7 | `0x5d2e090` | `Customizable::GetOptionsPtr` (96.15%) |
| 8 | `0x60956f0` | returns empty `Status` (C++ name open) |
| 9 | `0x609d0e0` | `Configurable::ConfigureOptions` (94.40%) |
| 10 | `0x60986b0` | `Configurable::ParseOption` (92.33%) |
| 11 | `0x6095710` | `Configurable::OptionsAreEqual` (90.58%) |
| 12 | `0x5fcdae0` | `SystemClockWrapper::SerializeOptions` (83.81%) |
| 13 | `0x609d980` | `Customizable::GetOptionName` (93.07%) |
| 15 | `0x5d32a30` | `Customizable::GetId` (87.88%) |
| 16 | `0x5d2e770` | `Customizable::IsInstanceOf` (93.81%) |
| 17 | `0x5fcc3f0` | returns `*(this+0x20)`, the wrapped clock (name open) |
| 18 | `0x5d2ca10` | returns `""` (name open) |
| 19 | `0x5d4d490` | `SystemClockWrapper::NowMicros` (98.45%) |
| 20 | `0x5fcc340` | forwards to wrapped slot 20 (`NowNanos`) |
| 21 | `0x5fcc360` | forwards to wrapped slot 21 (`CPUMicros`) |
| 22 | `0x5fcc380` | forwards to wrapped slot 22 (`CPUNanos`) |
| 23 | `0x5dd41a0` | `SystemClockWrapper::SleepForMicroseconds` (98.45%) |
| 24 | `0x5d4b100` | `GetCurrentTime` (canonical chain-walk) |
| 25 | `0x5fcc3a0` | `SystemClockWrapper::TimeToString` (95.77%) |

The wrapper is `0x30` bytes: `+0x00` vtable, `+0x08..+0x18`
zeroed by the ctor (exact container identity open), `+0x20`
`shared_ptr<SystemClock>` target, `+0x28` its control block.

## Three dispatch rules

- **Chain-walk** (slots 19, 23, 24): an 8-level unrolled walk. Each
  level's slot pointer is compared against the GOT canonical for
  that slot (slot 19: GOT `0x64ecf80` -> `0x5d4d490`; slot 23: GOT
  `0x64ed5f8` -> `0x5dd41a0`; slot 24: GOT `0x64ed3e8` ->
  `0x5d4b100`); the first level whose slot differs from the
  canonical is called; when all 8 compared levels match, the 9th
  level's slot is called unconditionally.
- **Single-level forwarding** (slots 20, 21, 22): a plain tail-jump
  to the wrapped clock's same slot (`mov 0x20(%rdi),%rdi; jmp
  *0xa0/0xa8/0xb0(%rax)`). No chain-walk, no canonical compare.
- **Slot 25** calls the wrapped clock's slot 25 with
  (`Status`-out, `this`).

## The neighbouring vtables

- `EmulatedSystemClock` (stored `0x64d1650`, typeinfo
  `N7rocksdb19EmulatedSystemClockE`) shares the wrapper's slots
  2-13, 15-18 and 25, and overrides 0, 1, 14 and 19-24. Its
  overrides add the emulated offset at `+0x40` (added to the
  wrapped time; `NowNanos` scales it by 1000), the sleep counter
  at `+0x38` and the CPU counter at `+0x3c` (each `lock addl $1`
  per call), and the flags at `+0x48/+0x49` (when `+0x48` is set,
  `NowMicros`/`NowNanos`/`GetCurrentTime` return the offset alone).
- `PosixClock` (stored `0x64ce930`, typeinfo
  `*N7rocksdb12_GLOBAL__N_110PosixClockE`) shares the wrapper's
  slots 2, 3, 4, 6, 7, 8, 9, 10, 11, 13, fills slots 0/1 with its
  own destructors, and uses the base `PrepareOptions`/`SerializeOptions`
  plus its own time methods. It is what identifies the shared
  slots: `Name()` -> `"DefaultClock"` (`0x431007`), slot 17 returns
  null, slot 18 returns `"PosixClock"` (`0x44768e`).

## The behaviours pinned end to end

- **GetOption** (slot 2): the `"id"` fast path — name length 2 with
  bytes `"id"` (`cmpw $0x6469`) calls slot 15 (`GetId`) on `this`
  and returns the id with an OK `Status`; any other name goes to
  the generic path `0x6099030`.
- **AreEquivalent** (slot 3): config flag `<= 1` or `this == other`
  returns 1; a null other returns 0; otherwise the two `GetId()`
  strings are `memcmp`'d; equal ids with flag `<= 2` return 1,
  equal ids with flag `> 2` tail-jump to the deeper check
  `0x60996a0`; different ids write `"id"` (`0x441b15`) into the
  out string and return 0.
- **PrepareOptions** (slot 5): when the target (`+0x20`) is null,
  install the default `PosixClock` via the accessor `0x5fe2680`
  with `shared_ptr` refcounting (the `0x64ed290`-selector `lock
  addl` vs plain `addl`, old control block released via
  `0x5d350c0`), then call the base
  `Configurable::PrepareOptions` `0x6095e70`.
- **GetId** (slot 15): calls slot 14 (`Name()`) on `this` and builds
  a `std::string` from the result via `0x5d32940`.
- **SerializeOptions** (slot 12): serializes via the base
  `Customizable::SerializeOptions` `0x609de80`, then checks the
  wrapped clock against the default clock (its slot-16
  `IsInstanceOf` against `"DefaultClock"`, compared with the GOT
  slot `0x64eceb8`).
- **Ctor C1** `0x5fd0090` (re-shipped from #3352's packet, byte-identical):
  installs the vtable, zeroes `+0x08..+0x18`, calls `0x6099ce0`.
  Its only direct caller in `.text` is `EmulatedSystemClock::C1`
  (`0x6029390`).
- **D0** `0x6029500` (by contract): deletes with size `0x30`,
  installs the base vtable `0x64d3420+0x10` mid-teardown.

## Evidence

- `records.json`: semantic records only — the three vtable maps,
  the chain-walk rule with GOT canonicals, the per-slot methods,
  the layout, the literals and the open unknowns. No
  per-instruction mnemonic list: instruction-level detail lives
  only in the verbatim excerpts.
- `*.objdump.txt`: whole-function objdump excerpts, exactly as
  objdump emitted them. Mnemonics such as `endbr64` are genuine
  instructions present in the target binary, not placeholders.
  Regenerate with `export_excerpts.py`.
- `census.py`: caller census (direct calls, tail jumps, whole-file
  qword hits, `R_X86_64_RELATIVE` slots) for all 40 targets.
  `callers.tsv` gives every site with its containing FDE and role.
- `verify.py`: `python3 research/work-items/RE-001-systemclock-wrapper-vtable-115/verify.py`
  — digest, manifest, excerpt regeneration, fixed + 3 seeded
  random gate spots byte-for-byte vs fresh objdump and the raw
  binary, frames, census reproduction + site verification in the
  containing FDE, model tests, RELATIVE-slot exactness, the three
  vtable maps, the literals and the model constants.
- `tools/systemclock_wrapper_vtable_115.py` + `tests/test_systemclock_wrapper_vtable_115.py`:
  the dispatch model (vtable dispatch, chain-walk, forwarding,
  `GetOption` id path, `AreEquivalent`, lazy default,
  `GetId`/`Name`/`IsInstanceOf`, emulated offsets/counters) with
  19 tests.

Objdump command (from the repository root):

```
objdump -d --start-address=<window start> --stop-address=<window end> work/hl-node-115.bin
```

## Open unknowns

- The C++ names of slots 4, 8, 17 and 18. `Configurable::GetOptionString`
  `0x6098510` and `Configurable::ToString` `0x60971c0` are ruled out
  as slot-4/8 identities: their census VAs are not in this vtable.
- The exact container identity of the wrapper's `+0x08..+0x18` range.
- How a bare wrapper answers `GetId`/`GetOption("id")` when its slot 14
  (`Name`) is null.
- The exact branch outcome of the `SerializeOptions` `IsInstanceOf`
  compare against GOT `0x64eceb8`, and the exact role of the
  emulated `+0x48/+0x49` flags in `Sleep`.
- The full internals of the shared `Configurable`/`Customizable`
  base methods (slots 2, 3, 6, 7, 9, 10, 11, 13): pinned here by
  identity, entry contract and callees; their bodies are the
  `Configurable` component's own work.
- Why the wrapper vtable leaves slots 0, 1 and 14 null while
  `EmulatedSystemClock` and `PosixClock` fill all 26 slots.

## Artifact

Node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

Environment limits: this VM has no cargo/rustc, no git-lfs and no
Ghidra/Java, so `make verify`, `make test` and `make catalogue-check`
could not be run here; the packet's own `verify.py` (digest,
manifest, excerpt regeneration, gate spots, frames, census, model
tests, vtable maps) passes instead.
