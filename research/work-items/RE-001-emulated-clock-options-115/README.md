# RE-001: pin node #115 the EmulatedSystemClock option maps' contents

Task: RE-001 (RocksDB options reconstruction).
Work item: `RE-001-emulated-clock-options-115`.

## Bounded question

What do the two option maps the EmulatedSystemClock ctor registers
(`0x6505960`, `0x6505920`) hold, which accessors do their records
bind, and what do the two flags at `+0x48`/`+0x49` do to
`SleepForMicroseconds` and `GetCurrentTime`?

## Answer (read from the binary)

### The maps' contents

The static initializer `0x6029d10..0x602a25d` populates both maps at
load time. It is installed in `.init_array` through a RELATIVE reloc
addend `0x602e4c0`; the 9-byte stub `0x602e4c0` (`endbr64; jmp
0x6029d10`) tail-jumps into it, so it runs at load time. It has no
direct `E8` caller anywhere.

| map | key | insert site | getter | setter |
| --- | --- | --- | --- | --- |
| `0x6505960` | `time_elapse_only_sleep` (literal `0x4476c8`) | `0x6029e6b` | `0x6025e50` | `0x6026ba0` |
| `0x6505920` | `mock_sleep` (literal `0x4331d7`) | `0x6029fff` | `0x6026100` | `0x6026ad0` |

Each key literal has exactly one `lea` site binary-wide, inside the
initializer (`0x6029d11`, `0x6029f0b`). Each map has exactly two `lea`
sites: the ctor's `RegisterOptions` call (`0x602942b` / `0x6029471`,
pinned by merged #3948) and the initializer's insert (`0x6029e50` /
`0x6029fe0`). The initializer builds each record with the record
builder `0x5e32920`, passing a 5-slot function-object table at
`-0x230(%rbp)`: slot `+0x10` holds the setter pair (manager, fn),
slot `+0x30` the getter pair, the other three slots are null.

The initializer also inserts a third entry, `supports_direct_io`
(literal `0x44657e`) into `0x65058e0` at `0x602a19a`. Its record is
built zeroed (no `0x5e32920` call in that block) and its group belongs
to another host (`0x6028a60`, `RegisterOptions` site `0x6028b3a`,
still unanalysed). It is recorded here as a lead, not claimed.

### The accessors

The getters read one flag byte and format it as `"true"` (literal
`0x43f883`) or `"false"` (literal `0x430e89`), returning a `kOk`
Status:

- `0x6025e50` (`time_elapse_only_sleep` getter) reads `+0x48`.
- `0x6026100` (`mock_sleep` getter) reads `+0x49`.

The setters parse the input with the bool parser `0x61d1480` and
write the result back, returning a `kOk` Status:

- `0x6026ba0` (`time_elapse_only_sleep` setter) writes the parsed
  value into **both** `+0x48` and `+0x49` (`xchg` into `+0x48`,
  `mov` into `+0x49`). Setting this option therefore also sets
  `mock_sleep` to the same value.
- `0x6026ad0` (`mock_sleep` setter) writes `+0x49` only.

The bool parser `0x61d1480..0x61d1504` accepts exactly four
spellings: `"true"` (len 4) and `"1"` (len 1) read true; `"false"`
(len 5) and `"0"` (len 1) read false. Any other spelling jumps to
the shared throw block at `0x61d1437` (allocates `0x10` bytes, throws
via `0x63f1960` / `0x63f1200`).

The four lambda managers are one `0x2d`-byte template: op 0 stores
the lambda typeinfo into `*rdi`, op 1 stores `rsi` into `*rdi`, any
other op returns 0. Their typeinfos name the option and the accessor
kind (`time_elapse_type_info` / `mock_sleep_type_info`, setter
signature `...SC_PvE_E`, getter signature `...PKvPSA_E_E`).

### What the flags do

`SleepForMicroseconds` (slot 23, `0x6025b40..0x6025b7f`) atomically
increments the sleep-call counter at `+0x38`; if `mock_sleep`
(`+0x49`) **or** `time_elapse_only_sleep` (`+0x48`) is set, it
advances the emulated-time offset at `+0x40` (microseconds) by the
requested duration; if `mock_sleep` is clear it also performs the
real sleep by delegating to the wrapped clock's slot 23; if neither
flag is set it delegates with no offset advance.

`GetCurrentTime` (slot 24, `0x6025eb0..0x6025feb`) returns the stored
emulated time at `+0x30` when `time_elapse_only_sleep` (`+0x48`) is
set, else delegates to the wrapped clock's slot 24 with the same out
slots; then, when the Status is `kOk`, **both** paths add the `+0x40`
offset converted from microseconds to whole seconds (signed division
by 1,000,000 via the magic-multiply idiom at `0x6025f92..0x6025fae`,
magic `0x431bde82d7b634db`). The offset-add is skipped on an error
Status (`jne 0x6025f03`). The ctor seeds `+0x30` from the wrapped
clock's slot 24 (pinned by merged #3948).

Object layout (fields this packet pins; the rest is merged #3948):

| offset | field |
| --- | --- |
| `+0x20` / `+0x28` | `shared_ptr<SystemClock>` wrapped clock (object / control) |
| `+0x30` | stored emulated time (`GetCurrentTime` value) |
| `+0x38` | sleep-call counter (`u32`, atomically incremented) |
| `+0x40` | emulated-time offset in microseconds |
| `+0x48` | `time_elapse_only_sleep` flag byte |
| `+0x49` | `mock_sleep` flag byte |

## Correction to prior work

Merged PR #3948 (`RE-001-systemclock-installers-115`) records that
the third fields of the ctor's two `RegisterOptions` records
(`0x6505960` / `0x6505920`) are "`.bss` (runtime-initialized); their
contents are not recoverable statically". That is superseded here:
the static initializer `0x6029d10` populates both maps at load time,
and its inserts, keys and accessors are pinned above. Nothing else
in #3948 is re-pinned: the ctor, its two callers, the factory, the
invokers, the dtors and the wrapper ctor are cited, not repeated.
`NowMicros` / `NowNanos` contracts are cited from
`RE-001-delegate-vtable-115` and the vendor census; the slot names
(slot 19 `NowMicros`, 20 `NowNanos`, 23 `SleepForMicroseconds`, 24
`GetCurrentTime`) come from
`RE-002-node115-rocksdb-clock-emulated-vtable`.

## Verification

`verify.py` ALL CHECKS PASSED (70/70: artifact digest, manifest,
excerpt regeneration, FDEs, raw-binary spot bytes, lea/E8 censuses,
Emulated vtable slots 19/20/23/24, manager typeinfo names,
semantic-only records, model tests); `pytest` on
`tests/test_emulated_clock_options_115.py` passes (13 tests).

## Open unknowns

- Final `OptionTypeInfo` record offsets: the record-init helper
  `0x5e32920` and transform `0x5d400f0` place the getter/setter
  pairs into the record; the table slots are pinned, the final
  record offsets are not.
- Why the `time_elapse_only_sleep` setter writes `mock_sleep` too:
  recorded as observed behavior; the upstream intent (whether
  time-elapse mode implies mocked sleep) is not pinned.
- The third insert's zeroed record: what `0x5d400f0` fills into the
  `supports_direct_io` record, and which host registers the
  `0x65058e0` group (host `0x6028a60`, site `0x6028b3a`).
- The `0x4fb647d0` fallback constant's unit (seconds since epoch
  would read 2012-05-14; the value is recorded verbatim).
- Slots 21/22 (`0x6025a30` / `0x6025a10`) and slot 25 (`0x5fcc3a0`)
  bodies: cited by address only.
