# RE-001: node94 shell retry schedule and explicit attempt budget

- Component: foundation shell/time helpers. Question: how does the actual retry
  entry distinguish default and empty schedules, what default bytes does it
  use, and where are the explicit attempt calls relative to exhaustion?
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Base and unchanged reference pins:
  `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Actual FDEs: retry `0x13c9080..0x13c9363` (**739 bytes**), selected exhaustion
  helper `0x14b5530..0x14b559e` (**110 bytes**). Complete native raw exports
  are retained. Helper semantics/trait calls are not closed.
- No captured executable, shell command, sleeping, filesystem operation or
  process spawn is performed; all analysis is static. No progress gate.

## Reference corrections

The unlicensed inferred `base/shell.rs` was a search lead. It gives default
sleeps `[0.001, 0.05, 0.1]`; the actual RIP-bound default table at VA
`0x216dd8` contains **[0.001, 0.05, 1.0]** as three binary64 values:

```
fca9f1d24d62503f  9a9999999999a93f  000000000000f03f
```

The final default is ten times the inferred value. These are target bytes,
not independently chosen retry policy or copied source implementation. The
reference also models another `wait_inner` call after exhausting the schedule.
The actual routine has only two decoded explicit call sites through the
observed wait slot: initial and loop. Exhaustion instead formats a diagnostic
and calls a distinct helper. The **explicit call-site budget** is therefore
initial plus one loop call per selected element, stopping early on a zero
result. This does not prove an absence of hidden effects in the unclosed
format/diagnostic/cleanup/wait helpers.

## Input, selection and control flow

The entry saves RCX as the schedule pointer and R8 as its length, original
RDI as the request object, and RSI/RDX as a description pair. It first calls
slot `0x576e8c8` at `0x13c90ad`, bound by RELATIVE addend to `0x13e4e40`.
A zero result returns zero without selecting or sleeping a schedule. Nonzero
results are retained as opaque error-like pointers, with virtual cleanup calls
shown in the raw disassembly; their exact Rust type is not recovered.

After an initial nonzero result:

| Machine inputs | Selection |
| --- | --- |
| RCX == 0 | fallback table `0x216dd8..0x216df0`, three f64 entries |
| RCX != 0, R8 == 0 | empty schedule; immediate exhaustion path |
| RCX != 0, R8 != 0 | selected pointer through pointer+8*length, one element per loop |

This is a machine-level null/default distinction, not a recovered Rust
`Option<&[f64]>` declaration or permission to pass arbitrary invalid slices.
No complete valid input/type domain or caller census is established.

After each selected interval, the loop calls the same wait slot at `0x13c9255`.
A zero result breaks successfully; a nonzero result replaces the saved pointer,
advances the schedule pointer by eight, and loops while it differs from the
computed end. On exhaustion, `0x13c928a..0x13c92f2` formats a descriptor at
`0x1fceaf`, calls the distinct helper `0x14b5530`, retains its returned value
in R14, cleans up the last pointer and returns R14. No additional decoded
call through `0x576e8c8` appears in that path or elsewhere in this 739-byte FDE.

The retained compact descriptor has literal fragments beginning
`sleep_retry retried`, `for sleep times` and `last err`; its raw length tags
and placeholders are saved without claiming full rendered output. The
110-byte helper calls slot `0x576fcd8` -> `0x4eeee40`, then directly calls
`0x14b5b70`. Both remain semantically unresolved; it is not certified as an
error constructor or as free of external effects. The complete observed
explicit budget should not be generalized to those unknown helper closures.

## Sleep and source bindings

At `0x13c9125`, each selected binary64 is multiplied by the data value
1,000,000.0 at `0x20ae60`. A longer inline finite/clamp/cast fragment then
forms seconds/remainder fields. Only the ordinary finite defaults are checked
numerically here: under normal binary64 evaluation they produce microsecond
integers 1000/50000/1000000 and timespec pairs `(0,1000000)`, `(0,50000000)`,
`(1,0)`. The retained integer fragment uses high-half multiplication by
`0x431bde82d7b634db`, shift 18, remainder from 1,000,000 and multiplication
by 1000. This is not a proof of its complete u64/f64 domain, altered floating
control states, wall-clock delays or scheduling behavior.

The indirect sleep target loaded into R12 from slot `0x576e8d0` is bound by
`R_X86_64_GLOB_DAT` (type 6) to **dynsym index 17, nanosleep**. The call at
`0x13c920d` passes the same `rsp+0x30` buffer as both RDI and RSI. Failure -1
calls slot `0x576e8d8`, **dynsym index 18, __errno_location**, and compares
its integer with raw immediate 4; other values reach the failure path.
The remainder reload/loop is retained. The Linux
[nanosleep interface](https://man7.org/linux/man-pages/man2/nanosleep.2.html)
provides the request/remainder interpretation; the routine itself is never
called here. No actual signal, delay or retry was generated.

Both explicit wait calls use Location slot `0x5666e38`, whose RELATIVE addend
is `0x1ef309`, path `/home/ubuntu/hl/code_Mainnet/base/src/shell.rs`, length 46,
line 48 column 32. This anchors source ownership, not exact inferred method
names, a complete shell API or a reconstruction build.

## Reproduce and controls

From repo root, with pinned captures materialized and native GNU tools:

```sh
python3 -B tools/shell_retry_static.py --output work/shell-retry-schedule-94
python3 -B tests/test_shell_retry_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-shell-retry-schedule-94/SHA256SUMS
```

Python 3.12.14, GNU readelf/objdump 2.47.20260726 on macOS. The generator
reads/authenticates one snapshot, then runs `readelf -wf` and
`objdump -d -M intel --insn-width=16 --start-address=... --stop-address=...`
on that private snapshot. No captured executable is launched or emulated.
The existing MIT `foundation_millis.decode_export` validates complete native
bytes/contiguity/extent. Independent transient Capstone 5.0.6 consumed all 739/110 bytes in 183/32
instructions respectively; this checks decoding, not helper semantics.
All retained controls/calls must be instruction starts,
and the two explicit wait-slot calls are counted over decoded instructions,
not an unvalidated raw-byte scan. Only temporary paths are normalized to
`<authenticated-node94>`; no instruction/data masks are used.

`frames.txt` and `.objdump.txt` preserve native evidence. `records.json` gives
original VAs/file offsets, hashes/sizes, exact schedule/descriptor bytes,
import/relocation/source bindings and observations/limits. SHA256SUMS covers
all packet files and the two new independently authored files.

Five focused tests cover real defaults and the three finite conversion vectors;
all **126** outcome sequences for schedule lengths 0..5 against an independent
first-success/budget expectation; **27** actual instruction/data/Location byte
changes plus replacement of the third default with the inferred **0.1**;
**4** actual RELATIVE-addend and **2** dynsym-index mutations; and native packet
regeneration. Corruption analysis occurs below the whole-input digest gate.
The outcome trace is an abstract path/count model and does not simulate command
execution or prove success/error helper semantics. Required suite/reproduction
results are recorded in the PR after completion.

## Gaps and next question

Concrete Rust types, incoming callers and valid schedule states, wait helper
implementation, dynamic cleanup targets, format/rendering and diagnostic
helper closure, arbitrary float conversion behavior, signal/scheduler timing,
independent Rust build and runtime equivalence remain unknown. No imports,
captures, pins, catalogue/progress or component gates change. Next validate
the actual callers that choose null versus explicit schedules before proposing
an independent API or changing retry policy.
