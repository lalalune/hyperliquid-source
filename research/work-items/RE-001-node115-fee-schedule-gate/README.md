# RE-001: node #115 fee-schedule ordering/range gate and its `fees.rs:259` window helper

- Component: `fees` (Fees and volume); bounded function-map and semantics packet.
- Target #115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: what does the only owner of the `l1/src/fees/fees.rs:259:57` Location compute, and which ordering/range predicates does its sole caller enforce before its shared `false` exit?
- Claim status: byte-derived observations plus conditional normal-path relations. Original symbols, source types and field names are not recovered. No Rust reconstruction, oracle or progress gate.

## Exact scope

| Role label | Actual FDE half-open VA range | Bytes | Claimed native instructions |
| --- | --- | ---: | ---: |
| window helper (owns `fees.rs:259:57`) | `0x36e1b10..0x36e1b81` | 113 | 33 (complete FDE) |
| fee-schedule validator (sole direct caller) | `0x36a1c20..0x36a31ff` | 5,599 | windows below only |

Claimed caller windows (half-open, instruction-aligned, natively decoded):
`chain 0x36a265e..0x36a2899` (122), `tail 0x36a2a0d..0x36a2a8b` (22),
`failure 0x36a2ad6..0x36a2c12` (78), `once 0x36a2c12..0x36a2c56` (10), plus
the seed/spill/binding instructions listed in `records.json`. Both complete FDE
bodies are hashed; the rest of the 5,599-byte caller is **not** mapped here.

The helper is the only owner of an LEA to Location slot `0x6468b98`
(`R_X86_64_RELATIVE` → path `0x431b81`, length 19, line 259, column 57). A
direct-`call`/`jmp` scan of `.text` finds exactly one caller, `0x36a283a`, and no
relocated pointer to the helper. That is a direct-reference census, not proof of
no other indirect use.

## The window helper

Input RDI points to a three-word state: cursor `+0`, remaining `+8`, window size
`+0x10` (the shape of a `[f64]::windows(n)` iterator; that type is an inference).
For size ≥ 2 the loop tests `size ja remaining` to exit, writes the advanced
cursor and decremented remaining back to the state, then executes
`ucomisd xmm0=[cur], [cur-8]` (next vs previous) and continues on `jbe`.
AL is `setbe(size <= remaining)` captured at the loop top, so:

- the first window whose second element is **strictly greater** than its first
  (ordered compare) returns AL=1;
- exhaustion returns AL=0; a NaN on either side satisfies `jbe` and is skipped.

For size < 2: an empty state returns AL=0; otherwise the state is advanced and
the call through slot `0x64df620` (`RELATIVE` → `0x1680cbf`) receives
EDI=1, ESI=1 and RDX=the `fees.rs:259:57` Location. `0x1680cbf` references the
template `" index out of bounds: the len is … but the index is …"` at
`0x4400ef`. This is a bounds-panic path for index 1 with length 1; its
unwind/panic behaviour is not claimed.

The only caller builds the state on its stack with size **2** (`mov QWORD PTR
[rsp+0x150],0x2` at `0x36a2826`) and fails on a nonzero AL (`jne 0x36a2ad6`),
so in this use the helper enforces **non-increasing order with NaN pairs
ignored**, and the bounds panic is unreachable from this caller.

## Caller: ordering and range predicates

All predicates below are decoded from the actual bytes (condition-code bytes,
operand order, entry thresholds, RIP-relative literals), not asserted.
`ucomisd` sets ZF=PF=CF=1 for unordered operands (Intel SDM, UCOMISD); the NaN
column follows from that and the decoded branch.

| # | Slice (ptr, len) | Elem | Decoded relation per adjacent pair | Pass on | NaN pair |
| ---: | --- | --- | --- | --- | --- |
| 1 | `[rsp+0x90]`, `[rsp+0x98]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 2 | `[rsp+0xa8]`, `[rsp+0xb0]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 3 | `[rsp+0xc0]`, `[rsp+0xc8]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 4 | `[rsp+0xd8]`, `[rsp+0xe0]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 5 | `[rsp+0x20]`, `[rsp+0x28]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 6 | `[rsp+0x38]`, `[rsp+0x40]` | f64 | continue if `next jbe prev` | non-increasing | passes |
| 7 | `[rsp+0x68]`, `[rsp+0x70]` | u64 | continue if `prev jb next` | strictly increasing | n/a |
| 8 | `r14`, `rbx` | f64 | continue if `prev jb next` | strictly increasing | **passes** (CF=1) |
| 9 | `[rsp+0x50]`, `[rsp+0x58]` | f64 | helper above, size 2 | non-increasing | passes |

Each loop exits to the next check when fewer than two elements remain
(`cmp len,2; jb` or `cmp len,1; jbe`), and fails through `jmp 0x36a2ad6`.
Note that check 8 is strict for ordered values but **lets NaN through**, because
`jb` reads CF, which an unordered compare sets. Only the pair list below rejects NaN.

**Pair list** — pointer/length loaded from `input+0x38`/`input+0x40`
(`rbp` = the spilled original RDI; see dataflow), 16-byte stride, both previous
values initialised to `+0.0`:

- first component: fail if `first jbe previous_first` → must be **strictly greater**, NaN fails;
- second component: continue if `second ja previous_second` → strictly greater, NaN fails;
- after the loop (or immediately when empty): fail if last first `> 5.0`
  (`0x4593d0`) or last second `> 0.5` (`0x459490`).

So a nonempty list needs both components strictly increasing from 0 with the
final pair at most (5.0, 0.5); an empty list passes.

**Scalar ranges** — the 16 bytes at `input+0x88` are copied to `[rsp+0x100]`
in the prologue (`0x36a1c6c`/`0x36a1c73`, the only store to `[rsp+0x100..0x10f]`)
and the high half is duplicated to `[rsp+0x110]` (`unpckhpd`). For each of
`input+0x88` and `input+0x90`: fail if `0.0 ja value` or `value ja 1.0`
(`0x4592b0`). Both bounds are inclusive; `-0.0` passes; **NaN passes** (neither
`ja` is taken on unordered). These two exit to `0x36a2ae4`, skipping the Once branch.

**Vector seeds** (element 0 only; later appends are not recovered): slices 1–4
start with `input+0x68`, `+0x70`, `+0x78`, `+0x80` respectively; slice 7 starts
with u64 `0`; slice 9 starts with f64 `1.0` (`0x3ff0000000000000`). The origins
of slices 5, 6 and 8 are not bound here.

## Failure result

`0x36a2ad6` loads a Once state word (`0x64f01d8`); if nonzero it calls through
`0x64df9f0` and returns with `jmp 0x36a2ae4`. From `0x36a2ae4` every branch
before `0x36a2bfe` is a forward conditional skip over deallocation calls
(`0x64df4a0`); the only RBX writes are `mov ebx,0` (`0x36a2b5d`) and
`mov ebx,ebp` (`0x36a2b78`, after `xor ebp,ebp` at `0x36a2b5b`), followed by
`mov eax,ebx` (`0x36a2bfe`) and `ret` (`0x36a2c11`). Assuming those calls return
normally and preserve callee-saved registers, **every failure above returns
EAX=0**. The success path (`mov bl,1` at `0x36a30ce`) lies beyond further,
unmapped checks (including `0x36a58d0`), so passing this gate does not establish
a `true` result.

## Dataflow cross-checks (`dataflow.json`)

From a native GNU CFG of the whole caller (direct edges; 1,150 instructions):
no RBX write on any direct path from `mov rbx,rdi` (`0x36a1c31`) to the spill
`[rsp+0x138]` (`0x36a1def`, its only store); no RBP write on any direct path from
the reload (`0x36a20ad`) to the pair-slice loads (`0x36a2847`). The caller's
two indirect jumps (`0x36a1f02`, `0x36a1f75`) are listed and are not reachable
on either of those paths. Aliasing stores through non-RSP pointers are not
excluded.

## Reproduce and validation

Python 3.13.18, Linux x86_64, GNU readelf/objdump 2.42. From repository root:

```sh
python3 -B tools/fee_schedule_gate_static.py --output work/fee-schedule-gate115
# compare generated files with this packet (excluding README/manifest)
python3 -B -m unittest discover -s tests -p test_fee_schedule_gate_static.py -v
make doctor verify test catalogue-check
(cd research/work-items/RE-001-node115-fee-schedule-gate && sha256sum -c MANIFEST.sha256)
```

The public entry authenticates the full capture before parsing. `certificate()`
decodes every claimed predicate from bytes; `_analyze()` additionally pins both
FDEs, both body hashes, the Location, both relocations, the panic template,
seeds, input bindings and the failure return. `generate()` cross-checks FDEs
with `readelf -wf`, instruction starts with `objdump`, the two relocations with
`readelf -rW`, and the CFG dataflow above.

Six focused tests cover byte-identical regeneration; decoded predicates including
NaN, `-0.0`, empty and single-element slices; helper behaviour including the
`(index 1, len 1)` panic case; pair caps at the exact boundary (5.0, 0.5); and
range bounds. Six **semantic counterfactuals** mutate real bytes and show the
certificate changes meaningfully (`jbe→jb` on a back-edge, `jb→jbe` on the u64
check, window size 2→1, the helper's back-edge, the shared 5.0 literal, and
`ja→jae` on a range test). Fifteen **corruption controls** below the public
identity gate (branch targets, element displacement, comparison register, the
helper result gate, pair slice field, cap/range targets, Location displacement
and line, panic index, a seed field, the spill slot, the failure return value,
and an unrelated caller byte caught by the body hash) are each rejected.

Model note: the Python predicates interpret the decoded certificate with
x86 CF/ZF semantics; they are an independent reading of the bytes, not a CPU
emulator, and passing them does not validate any reconstruction.

Observed local results: the six focused tests passed in 18.5 s. The required
`make doctor verify test catalogue-check` result is recorded in the pull request
exactly as observed. No hosted CI result is claimed.

No captured executable/emulator, configuration file, oracle update, signing,
wallet, network or chain action was used. Imports, pins and all gates are unchanged.

## Relation to retired #94 evidence (PR #128)

PR #128 (merged as `13bbb2d`, packet `fees-schedule-admission-94`, retired by
the #115 migration) mapped the #94 validator `0x3c02dc0`. Its labels are
**leads only** here: no #94 address, offset or name is inherited, and nothing
below is required by the #115 claims above. Read side by side with its
`checks.tsv`/`fields.tsv` at that commit:

| #94 row (label, seed/offset) | #115 observation in this packet | Status |
| --- | --- | --- |
| 1–4 cross/add/spotCross/spotAdd non-increasing, seeded `+0x48..+0x60` | slices 1–4 non-increasing, seeded `+0x68..+0x80` | same relation; seed offsets **+0x20** |
| 5–6 mm add / spot mm add non-increasing | slices 5–6 non-increasing | origins unbound in #115 |
| 7 ntl u64 strictly increasing, seeded 0 | slice 7 u64 strictly increasing, seeded 0 | consistent |
| 8 makerFractionCutoff strictly increasing, seeded 0.0 | slice 8 strictly increasing for ordered values; **NaN passes** | seed unbound in #115 |
| 9 vip word non-increasing, seeded 1.0 | slice 9 = outlined `fees.rs:259` helper, seeded 1.0 | consistent; helper is outlined in #115 |
| 10–13 stake bps/discount, previous 0.0, caps 5.0 / 0.5; Vec ptr `+0x38`, len `+0x40`, stride 16 | pair list at `+0x38`/`+0x40`, stride 16, previous 0.0, caps 5.0 / 0.5 | same offsets and literals |
| 14–17 keep `+0x70` and referral `+0x68` in [0, 1], "silent" exit | `+0x90` and `+0x88` in [0, 1], separate exit `0x36a2ae4` that skips the Once branch | offsets **+0x20**; test order differs (see below) |

Preserved mismatches: #94 orders the range tests keep-high, referral-low,
referral-high, keep-low; #115 tests `+0x88` low/high then `+0x90` low/high.
#94 recorded that non-finite inputs were not analysed; this packet supplies the
#115 NaN behaviour (ordered lists 1–9 accept NaN pairs; the pair list rejects NaN;
the two ranges accept NaN). The "loud/silent" distinction in #94 is consistent
with the two #115 failure entries (only `0x36a2ad6` touches the Once state),
but no logging behaviour is claimed here. #94 rows 18–28 and the floor function
have no counterpart in these windows.

## Limits and next question

Not claimed: what the validated struct is in source terms, field names, what
populates vector elements after element 0, origins of slices 5/6/8, the
`0x3d3b6c0` gate before the chain, the post-gate checks and success path, all
callers of the validator, and panic/unwind/allocator-failure behaviour.

Next question: bind the per-record append loop at `0x36a1e40` (48-byte records
from `input+0x08`/`+0x10`) to slices 1–9 so that each ordering check can be
attributed to a concrete record field.
