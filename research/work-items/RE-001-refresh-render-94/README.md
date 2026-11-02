# RE-001: refresh-then-render BlockCache accessor, node #94

Bounded question: what does node #94 `0x514fd60` do end to end?

## Answer

`0x514fd60` (0x514fd60..0x514ffd8, FDE 0x006341b0) is the
refresh-then-render accessor for the BlockCache report. It takes an
outer object, a destination string and a flag byte, and returns 1
on the render path, 0 when the inner object is null.

1. **Null guard.** If `[outer+0x128]` is 0, it returns 0 with the
   destination untouched; no refresh, lock or render is attempted.
2. **Refresh, flag inverted.** Otherwise it calls the timed
   snapshot refresh `0x514f270` with the flag byte XOR 1, then
   re-reads `[outer+0x128]`.
3. **Lock.** It locks the inner object's own mutex
   (`pthread_mutex_lock` on the inner object); a nonzero result
   throws `system_error`.
4. **Copy.** It copies the whole 0x138-byte published snapshot at
   `inner+0x28` onto the stack at `rsp+0x20`. Every range moves by
   vector copy except the string slot at snapshot `+0x20`, which
   is copied by `_M_assign` from `inner+0x48` into the stack
   string at `rsp+0x40`. The tail fields at snapshot `+0x120`
   and `+0x128` come from `inner+0x148` (8 bytes) and
   `inner+0x150` (16 bytes). The stack slots at snapshot `+0x120`
   and `+0x128` are zeroed before the lock and then overwritten
   by the copy (recorded as observed).
5. **Unlock, then render.** It unlocks the inner mutex BEFORE
   calling the formatter `0x514f770` with the temp string at
   `rsp+0x00`, the stack snapshot at `rsp+0x20` and the clock
   holder at `[outer+0x780]`. The formatter constructs the temp
   string in place (it writes the SSO pointer, length 0 and NUL
   byte itself before replacing the content), so the temp needs
   no prior initialization.
6. **Assign and dispose.** It move-assigns the temp string into
   the destination (`0x514b4f0`), disposes the temp string and
   the snapshot's identity string (sized delete only when each
   pointer differs from its own SSO buffer), and returns 1.

## Reaching path

The window itself has no direct caller, tail jump or qword
reference in `.text`. It is reached through two tail-jump thunks
that fix the flag byte: `0x514ffe0` passes flag 0 (so the refresh
receives flag 1, the aggressive thresholds) and `0x514fff0`
passes flag 1 (so the refresh receives flag 0). Neither thunk has
a direct caller either, so their reaching path is unclaimed.

## Exception cleanup

`0x514fd30..0x514fd60` (FDE 0x006341fc) has two entries: the full
entry unlocks the mutex and then disposes the snapshot identity
string; the dispose-only entry disposes just that string. Both
check the canary and call `_Unwind_Resume`. The cleanup never
disposes the temp string. Which landing stub serves which call
site is not claimed (LSDA mapping).

## Callees (cited, not re-claimed)

- `0x514f270` timed snapshot refresh (RE-001-timed-snapshot-94):
  flag 0 gives thresholds (500, 180000000), nonzero gives
  (10, 10000000); this window inverts the flag.
- `0x514f770` BlockCache report formatter
  (RE-001-blockcache-report-94): renders the header plus entry
  stats into the destination string.
- `0x514b4f0` string move-assign (bound by the move-assign
  packet).

## Evidence

All excerpts are whole functions, verbatim from objdump on the
digest-verified binary (`work/hl-node-94.bin`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching `provenance/artifacts.json` for node #94):

- `window.objdump.txt` — `0x514fd60..0x514ffe0` (function plus
  int3 padding to the next FDE)
- `cleanup.objdump.txt` — `0x514fd30..0x514fd60`
- `thunk0.objdump.txt` — `0x514ffe0..0x514fff0` (thunk plus int3
  padding)
- `thunk1.objdump.txt` — `0x514fff0..0x514fffe`
- `frames.txt` — the four FDE lines
- `relocations.txt` — the PLT stubs used, with GOT addresses
- `records.json` — semantic records only (no per-instruction
  mnemonic list; instruction-level detail lives only in the raw
  excerpts above)
- `verify.py`, `export_excerpts.py` — the packet's own checks
  and excerpt generator

The Python model is `tools/foundation_refresh_render.py`, tested
by `tests/test_foundation_refresh_render.py`. It models this
window's control flow and copy; the refresh and the formatter
are injected callbacks, not re-implementations.

## Unknowns

- The identities of the outer, inner and clock-holder objects
  and what the report means to its readers.
- The reaching path of the two flag thunks.
- Which landing stub serves which call site.
- Why the pre-lock zeroing of snapshot `+0x120`/`+0x128`
  exists when the copy overwrites both.
