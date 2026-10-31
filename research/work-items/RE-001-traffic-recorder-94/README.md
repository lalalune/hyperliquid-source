# RE-001: node #94 traffic-recorder seed family

- Component: `transport`; bounded static seed validation under RE-001, which has
  no prerequisites. This is not completion of RE-001 or any transport gate.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its `net_utils/src/tcp/traffic_recorder.rs` leading comments supplied the six
  seeds and the claims under test; no code was copied.
- Question: do the six imported traffic-recorder seeds name real node #94
  function boundaries, and which of the reference's claimed poll-loop,
  drain, counter, sleep, and string semantics survive byte-level validation?

## Reproduce

Python 3.10+ plus a disassembler for the caller census: `llvm-objdump` (located
via `LLVM_OBJDUMP`, `PATH`, or the Homebrew LLVM prefixes) or GNU `objdump`.
The captured executable is only read as data; no command below launches it,
contacts a node, signs, or executes anything.

```sh
make doctor
make verify test catalogue-check
python3 tools/traffic_recorder_static.py --output work/traffic-recorder-94
diff -ru research/work-items/RE-001-traffic-recorder-94/observed work/traffic-recorder-94
python3 -m unittest tests.test_traffic_recorder_static -v
```

`observed/` was produced with Homebrew llvm-objdump 22.1.8 on darwin 24.6.0
(arm64), Python 3.15.0. Other disassembler versions may render the excerpt text
differently; compare `records.json` and the byte controls, which are independent
of the renderer. The tool authenticates the input by SHA-256 before analysis,
decodes the FDE ranges itself from `.eh_frame`, streams the complete `.text`
disassembly once for the direct-caller census, and checks 32 instruction-level
byte controls plus 6 string anchors.

## Evidence

All six seeds each begin their own FDE. Decoded half-open ranges (VA):

| Role | Seed/entry | Range |
| --- | --- | --- |
| Per-recorder poll, copy A | `0x3D13CD0` | `0x3D13CD0..0x3D1438D` |
| Per-recorder poll, copy B | (second copy) | `0x3D14390..0x3D14819` |
| Report task | `0x3D21670` | `0x3D21670..0x3D2198F` |
| Sleep-from-f64 poll | `0x3D0EEE0` | `0x3D0EEE0..0x3D0F26A` |
| Format helper 1 | `0x3D1DA50` | `0x3D1DA50..0x3D1DDD8` |
| Format helper 2 | `0x3D1DDE0` | `0x3D1DDE0..0x3D1E168` |
| Format helper 3 | `0x3D1E500` | `0x3D1E500..0x3D1E82D` |

Direct-call census over the full decoded `.text` (indirect dispatch excluded):

| Callee | Call sites |
| --- | --- |
| poll A `0x3D13CD0` | `0x3CFD416` (inside `0x3CFD380..0x3CFD496`) |
| poll B `0x3D14390` | `0x3CFDDF4` (inside `0x3CFDD60..0x3CFDEE6`) |
| report `0x3D21670` | `0x3D13B5C` (inside `0x3D13840..0x3D13CC9`) |
| sleep `0x3D0EEE0` | `0x3D12B0B`, `0x3D14039` |
| format `0x3D1DA50` | `0x3D14126`, `0x3D2175E` |
| format `0x3D1DDE0` | `0x3D12C31`, `0x3D21B7A` |
| format `0x3D1E500` | `0x3D12CB1`, `0x3D21BF1` |

Verified observations, each pinned by byte controls in `observed/records.json`:

1. **Atomic pending drain.** Both poll copies drain the shared counter with
   `xorl ecx,ecx; xchgq %rcx,0x10(inner)` — copy A at `0x3D13D92`, copy B at
   `0x3D14463` (both sites named by the reference, both confirmed).
2. **First-sample one-shot.** A byte flag at future+`0x168` (copy A) gates a
   once-only path that adds the creation-to-now elapsed nanos to stats+`0x58`
   and increments stats+`0x18`. Copy B repeats the same shape.
3. **Overrun gate.** Drained bytes are compared against a per-future budget
   (future+`0x160` copy A, future+`0xE0` copy B). Only strictly greater drains
   increment stats+`0x20` and add `bytes - budget` to stats+`0x60`, with an
   underflow guard branching to a panic path.
4. **Empty drains record nothing.** `bytes == 0` jumps directly to the waker
   handoff; non-empty drains increment stats+`0x28` and add elapsed to
   stats+`0x68`.
5. **Waker handoff.** `0x3D13ED1..0x3D13F7D` is a small cmpxchg state machine
   on inner+`0x28` (states 0/1/2) replacing or waking a single stored waker,
   inside the range the reference named.
6. **30-second cadence, twice.** Both poll loops arm their sleep future from an
   inline `movabsq $0x403E000000000000` (30.0): copy A at `0x3D1412B` storing
   future+`0xB8`, the report task at `0x3D21763` storing future+`0xD8`. Copy A
   polls its future through the shared sleep-from-f64 function `0x3D0EEE0`
   (call at `0x3D14039`); the report task polls its future through `0x3D1E830`
   (call at `0x3D21785`), a function this packet does **not** validate.
7. **Shared global bucket table.** After the sleep resolves, both copy A and
   the report task take the same global one-byte lock at `0x5786480`
   (`lock cmpxchgb` at `0x3D14076` / `0x3D217C2`) before draining the global
   bucket table and formatting through `0x3D1DA50`.
8. **String anchors.** `tcp_traffic` `0x5BC78D`, `traffic_logger` `0x5BC798`,
   `In` `0x5BC7A6`, `Out` `0x5BC7A8`,
   `profiled_rw_lock_increment` `0x5BC7AB`, and the std panic text
   `overflow when adding duration to instant` at `0x7CE45A` (referenced by
   copy A's instant arithmetic at `0x3D13FEA`) all match byte-for-byte.

Corrected inference (observation plus arithmetic, not a reference claim): the
reference stores *elapsed time* as the per-future budget
(`last_drain_budget_nanos`). The bytes do something else. After a non-empty
drain, the binary computes `(bytes >> 9) * 0x44B82FA09B5A53 >> 75` — a
division by exactly 10^9 — and **adds that many seconds (the byte count read as
nanoseconds) to the stored sample instant**, with the std instant-add overflow
panic armed. The magic multiplier is exactly `ceil(2^75/5^9)` and
`ceil(2^84/10^9)`; the division identity is verified exhaustively below 2^24,
at 2^55-scale boundaries, and at 10^6+ deterministic samples across `[0, 2^55)`
(`magic_division` in `records.json`). The elapsed added to stats+`0x68` is then
measured against that byte-advanced instant, not against the previous poll
time, and the paired per-direction totals at stats+`0x40/+0x48` (counts) and
stats+`0x80/+0x88` (bytes) are selected by comparing the derived whole-seconds
value against stats+`0xa0`. Full-domain validity of the division identity for
every 64-bit input is an inference from the standard invariant-division
construction, not an exhaustive check.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no build, no comparison harness.
This packet is static evidence only; every claim above is machine-checked
against the authenticated binary bytes by `tools/traffic_recorder_static.py`
and its corruption controls in `tests/test_traffic_recorder_static.py`.

## Results and limitations

- 6/6 seeds validated as real FDE starts with exact boundaries; 32 instruction
  byte controls and 6 string anchors over an explicit denominator of 38 checks;
  7-callee direct-call census exact.
- The reference's xchg sites, one-shot first-sample accounting, overrun gate,
  empty-drain behavior, waker range, 30-second cadence, sleep-from-f64 role,
  shared global lock, tracing strings, and stats offsets `0x18/0x20/0x28/0x58/
  0x60/0x68/0x40/0x48/0x80/0x88` are confirmed. Its *elapsed-as-budget* model
  is corrected above; its `first_update_seen`/counter field names remain
  inferred labels, not recovered names.
- Not covered: indirect callers (async executor dispatch), the bucket-table
  iteration callee `0x3D2B7B0`, the report task's sleep poller `0x3D1E830`
  (called at `0x3D21785`; relationship to `0x3D0EEE0` unexamined), formatting
  helper internals, `#115` drift, and any runtime behavior. No component gate
  is requested; transport gates stay false. Next bounded question: the
  bucket-table drain callee `0x3D2B7B0` and the label strings keyed into it,
  then the `0x3D1E830`/`0x3D0EEE0` sleep-poller pair.
