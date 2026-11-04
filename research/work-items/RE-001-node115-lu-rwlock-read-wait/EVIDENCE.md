# RE-001-node115-lu-rwlock-read-wait: bounded question

- Component ID: `base/src/lu.rs` conversion context, family wait FDE
  `0x5bb1a60` (RwLock read acquisition with a deadline).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit:
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main,
  node-115-only migration).
- Claim status: observation for the fast path, the acquire phase,
  the TLS gate, the bucket claim/enqueue, the futex wait, the
  timeout unlink, the panic paths, and the caller census; inference
  for the "RwLock read acquisition" framing (grounded in the
  overflow panic message's own wording plus the reader-count
  increment shape); unresolved for the mode byte's meaning, bit 2's
  role, bit 3's setter, the TLS check's semantics, the
  constructor's field values, the remaining-time flag's exact
  semantics, and the `+0x10 == 1` wake signal's writer.
- Scope included and excluded: included is the `0x5bb1a60` body only
  (1706 bytes, eh_frame FDE `0x5bb1a60..0x5bb210a`). Excluded are
  the lookup, park, cleanup, contention-helper, table-creation,
  constructor, timed-wait, and timeout-handler bodies (prior claims
  or context, cited by address only) and the callers' code (the
  127 GOT call sites are counted, not decoded).

## Reproduce

Working directory: a checkout of upstream main at the base commit
above. The node binary is `artifacts/node/115/hl-node`; it is never
executed. Commands (all static):

- `sha256sum artifacts/node/115/hl-node` → the target digest above.
- `objdump -d -M intel --start-address=0x5bb1a60
  --stop-address=0x5bb210a artifacts/node/115/hl-node` →
  `fde1a60.objdump.txt` (426 instruction lines, 9 nop paddings).
- Wait bytes: file offset VA − 0x1000 for `.text` →
  `fde1a60.hex` (1706 bytes, SHA-256
  `95d9b142970398a722b871c66eb3d77a3b06ae45a55333dc5c668b3773f96aac`).
- `readelf --debug-dump=frames-interp` → FDE
  `pc=0x5bb1a60..0x5bb210a`, CIE `0x39672c` (`zPLR`).
- `readelf -r` → GOT resolutions, self GOT slot, and panic
  `Location` relocations (see Evidence).
- `python3 tools/node115_lu_rwlock_read_wait.py` → exit 0.
- `python3 -m unittest tests.test_node115_lu_rwlock_read_wait` → 7/7.

No declared execution or side effects; no network, no node run.

## Evidence

Coordinates are ELF virtual addresses (PIE). `.text` file offset =
VA − 0x1000, `.data.rel.ro`/`.got` file offset = VA − 0x2000,
`.rodata` file offset = VA.

Validated boundaries: FDE `0x5bb1a60..0x5bb210a` (eh_frame),
single `ret` at `0x5bb20a2`, body proper 1603 bytes, panic stubs
plus landing pads 103 bytes, next function `0x5bb2110`.

Signature: `wait(rdi = slot, esi = mode byte (low byte only),
rdx = deadline seconds, rcx = deadline nanoseconds) -> u8`.
Returns 1 on fast-path increment or wake (`+0x10 == 1`), 0 on
timeout unlink; anything else loops internally.

Fast path: `lock cmpxchg [slot], word + 0x10` at `0x5bb1aee` and
`0x5bb1b4e`; success returns 1. Entry checks: mode byte nonzero
→ `(word & ~7) == 8` skips to the acquire phase; mode byte zero
→ bit 3 set skips to the acquire phase. Overflow of the add
panics with `RwLock reader count overflow` (see Panic paths).

Acquire phase: round counter in `edx` (reset on retry, carried in
`r14d`); while low 2 bits clear and rounds < 10, `2^(round+1)`
pauses per round, `sched_yield` (GOT `0x64e1558`) from round 3
(call `0x5bb1d68`); then `lock cmpxchg [slot], word | 0x1` at
`0x5bb1bb4`, or proceed when bit 0 is already set.

TLS gate: gate byte at `fs:[-0x4b0]`; `1` → per-thread node at
`fs:0 - 0x4d8` directly; otherwise TLS check `0x5bb5130` (node,
`0`) → nonzero returns a node, zero builds a stack node at
`[rsp+0x80]` via constructor `0x5bb6070` (GOT `0x64ec170`, call
`0x5bb2038`), marked by `[rsp+0x78] = 1` for the refcount
`lock dec` (GOT `0x64ec168` → `0x64fff20`) on exit/unwind paths.

Bucket claim (lookup shape inlined, lookup never called): table
variable GOT `0x64ec148` → `0x64fff28`; shift `64 -
[table+0x18]`; bounds against `[table+0x8]`; stride 64;
`lock cmpxchg 0 -> 1` at `0x5bb1c37`; contention helper GOT
`0x64ec160` on race; table creation GOT `0x64ec158` →
`0x5bb6400` on null; release-then-cleanup on table change
(cleanup GOT `0x64ec150` → `0x5bb66b0` exactly when old `>= 4`
with bit 1 clear). Enqueue requires slot-word bits 0 and 3 both
set; otherwise the bucket is released and the function retries.

Waiter node: `+0x0` slot key, `+0x8` link (`0`), `+0x10` status
(`1` = woken), `+0x18` = `0x10`, `+0x20` futex word (`1`),
`+0x24` has-deadline byte. Tail-append to `[bucket+0x8]` /
`[bucket+0x10]`; bucket released with `lock xadd -1`.

Futex wait: `syscall(202, word, 0x80, 1)` at `0x5bb1dd0`
(untimed, register-indirect) and `0x5bb1e5c` (timed, GOT-direct
with `r8 = [rsp+0x30]`). Sentinel: deadline nanos `== 10^9` →
untimed; otherwise `clock_gettime` wrapper `0x5c842e0` then
remaining-time helper `0x5c84210` per wake; expiry flag at
`[rsp+0x28]` → zeroed timespec (single poll) when set.

Wait exit: `cl = ([node+0x10] == 1)` at `0x5bb1df1`; set →
return 1, clear → retry. Timeout path: handler `0x5bb3ca0`
(call `0x5bb1f09`) returns `(key, entry)`; futex word 0 →
release and normal exit; otherwise bucket-list walk, unlink,
`lock and [slot], ~1` at `0x5bb1fc3` iff the key appears nowhere
else, bucket release, return 0.

Panic paths: overflow stub `0x5bb20a3` (message
`0x93fcd4`, 28 bytes, `RwLock reader count overflow`, Location
`0x64bd230` → raw_rwlock.rs:707:30 via addend `0x43bdae`,
length 67); subtract stub `0x5bb20bc` (Location `0x64bd260` →
parking_lot.rs:352:45 via addend `0x44f892`, length 73); shift
stub `0x5bb20cb` (Location `0x64bd278` → parking_lot.rs:352:5);
bounds stub `0x5bb20da` (Location `0x64bd290` →
parking_lot.rs:363:23). All four Location file fields read 0 in
the file and resolve through `R_X86_64_RELATIVE` addends.

Caller census: 0 direct `E8` callers (byte scan over all of
`.text`); 127 GOT-indirect `FF 15` call sites via slot
`0x64e0fd8` (→ `0x5bb1a60`); no register-indirect loads from the
slot. Internal calls: cleanup ×5, table creation ×1, helper ×1,
constructor ×1, syscall ×2, yield ×1, clock wrapper ×1,
remaining-time ×1, handler ×1, TLS check ×1, panic wrappers ×4,
`_Unwind_Resume` ×1, refcount `lock dec` ×2.
