# Foundation sentinel-increment helper (node #94)

A 30-byte single-call window at `0x327b210` that calls `0x3597020` with
pass-through arguments, then increments a field of the returned object —
unless the field holds the `-1` sentinel, in which case it stays `-1` —
and returns with `rax` restored. One call, one load, one increment, one
conditional move, one store: no branch, no loop, no flag test other than
the `inc` itself, no constant pool, no second call. The callee's
behavior is excluded from the rule; only its identity and extent are
locked.

## Rule

Call `0x3597020` with the window's incoming arguments unchanged, then
store `(old == -1 ? -1 : old + 1, wrapping)` as a qword to `[obj+0x20]`,
where `obj` is the callee's return value in `rax` and `old` is the
previous value of that field. Then `ret`, with `rax` restored to its
incoming value by the closing `pop rax`.

In other words: the field counts up by one on each call, except the
`-1` value is sticky — once the field reaches `-1` it never moves
again, and a field of `-2` increments into `-1` and then sticks. The
stickiness comes from the `inc` itself: `inc rcx` sets ZF exactly when
the incremented value is zero, which happens exactly when the old value
was `-1`, and `cmovne` keeps the `-1` in that case. No separate
comparison instruction exists in the window.

## Window

| Field | Value |
| --- | --- |
| Start | `0x327b210` |
| End (exclusive) | `0x327b22e` |
| Size | 30 bytes |
| FDE section offset | `0x00104048` |
| FDE CIE | `0x00000000` |
| Padding | 2 bytes `cc` (int3) to the next FDE at `0x327b230` |
| Body SHA-256 | `b58ca0301ff4ef99320862e6ba60ea112732924de3d9e05574c28f6096d7515b` |
| Target | node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Worktree HEAD | `2993e46` |

Instruction walk, in order:

| Address | Instruction | Role |
| --- | --- | --- |
| `0x327b210` | `push rax` | Save the incoming `rax` (also aligns the stack for the call) |
| `0x327b211` | `call 0x3597020` | The single call; arguments pass through unchanged |
| `0x327b216` | `mov rcx, [rax+0x20]` | Load the old field value |
| `0x327b21a` | `inc rcx` | Increment; sets ZF exactly when the result is zero, i.e. when old was `-1` |
| `0x327b21d` | `mov rdx, -1` | The sentinel value |
| `0x327b224` | `cmovne rdx, rcx` | Keep `-1` if ZF is set (old was `-1`), else take the incremented value |
| `0x327b228` | `mov [rax+0x20], rdx` | Store the new field value |
| `0x327b22c` | `pop rax` | Restore the incoming `rax` |
| `0x327b22d` | `ret` | Return; the window has no tail jump |

The window starts with `push rax`, not `endbr64`; its FDE range is
still `0x327b210..0x327b22e`. The window's return value is the
incoming `rax`, not the callee's return: the stored field is the
window's only observable effect in this packet.

## Callee

| Field | Value |
| --- | --- |
| Start | `0x3597020` (an FDE start) |
| End (exclusive) | `0x3597192` |
| Size | 370 bytes |
| FDE section offset | `0x00151884` |
| FDE CIE | `0x00000000` |
| Padding | 14 bytes `cc` to the next FDE at `0x35971a0` |
| Body SHA-256 | `62a7dcf9363b2b6e8be596ba401687524272180271d5a29573763c76ccb6f7ec` |

The callee is called from exactly one direct site in `.text`: this
window (`0x327b211`). No other small-band window shares this callee,
so the shared-callee question does not arise. Because the callee is 370
bytes, its body is locked by length, SHA-256 and padding rather than by
locking every one of its instructions; that locks its identity and
extent, which is all the rule uses.

## Neighbors

| FDE start | Size | Relation |
| --- | --- | --- |
| `0x327b180` | 131 bytes | Previous FDE; unrelated |
| `0x327b230` | 693 bytes | Next FDE after the window; unrelated |
| `0x3597020` | 370 bytes | The callee (above) |
| `0x35971a0` | 446 bytes | FDE after the callee; unrelated |

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x327b210`
finds exactly zero sites, so this packet has seven files (no
`caller.objdump.txt`). Register-indirect references, other pointer paths,
prefixes, and data sections are not a complete xref census, so the claim
is scoped to direct `e8` calls, not to all possible references.

## Twins and uniqueness

Raw FDE bytes, position-wise equal bytes, no normalization. Two claimed
cohorts: A = claimed windows present in the 20–150B single-call census
(30 windows, including #152); B = every claimed window from every
`evidence.json` in prior worktrees and the main tree (32 windows).

- Against claimed windows: maximum similarity 0.133 max-length
  (cohort A: at `0x4f9ee90`, the #147 window; cohort B: same window),
  well below the 0.60 cutoff.
- Against the full corpus of 31,898 single-call FDE windows: best
  non-self 0.167 max-length (at `0x538fb30`, 29 bytes: a call + lea/add
  + store window with a different rule) and 0.200 min-length with the
  20-byte floor (at `0x134cc70`, 72 bytes: a larger window sharing only
  short prologue bytes).
- The mnemonic skeleton (`push call mov inc mov cmovne mov pop ret`)
  is a singleton among 31,898 single-call FDE windows of 20-150 bytes,
  and this window is the only single-call census window calling
  `0x3597020`.
- Measure validation: the same procedure reproduces #152's
  claimed-best 0.250 max-length (cohort A at `0x54d6360`, cohort B at
  `0x55243d0`) and corpus-best 0.438 / 0.500 exactly, and #151's
  claimed-best 0.211 max / 0.235 min and corpus-best 0.333 / 0.439
  exactly.

## Rule edges

| Old value | Stored | Model |
| --- | --- | --- |
| `0x0` | `0x1` | Ordinary increment |
| `0x5` | `0x6` | Ordinary increment |
| `0xffffffffffffffff` (-1) | `0xffffffffffffffff` | Sentinel sticks: `inc` yields 0, ZF set, `cmovne` keeps `-1` |
| `0xfffffffffffffffe` (-2) | `0xffffffffffffffff` | Increments into the sentinel, then sticks on later calls |
| `0x7fffffffffffffff` | `0x8000000000000000` | Wraps past the signed maximum; recorded as an edge, not a fault |

The edges are model checks on the recorded arithmetic, not executions
of the target binary. The increment wraps modulo 2^64; only the `-1`
value is sticky.

## Rejected candidates

| Address | Reason |
| --- | --- |
| `0x552d630` / `0x552d650` (28 bytes each) | Near-identical twin pair differing only in the constant (`0xe` vs `0xf`): call a PLT import, `test` + `setne`. Picking one would leave a 27/28-byte near-twin in the corpus; the rule is also a bare boolean test. |
| `0x5454770` (42 bytes) | Call then `mov eax, 1`: the call result is discarded and a constant returned; no computation on the result. |
| `0x53f24a0` (42 bytes) | Call then `xor eax, eax`: the call result is discarded and zero returned. |
| `0x4fce840` / `0x4fcf4a0` (35 bytes each) | Identical argument-marshalling wrappers: push stack arguments, call, restore, return; no post-call computation. |
| `0x472a5f0` (26 bytes) | Call then tail-call through a GOT slot with fresh constants: the first call's result is unused; a chaining adapter. |
| `0x5529440` (40 bytes) | Call then tail-call to another PLT import with reshuffled arguments (variadic setup, `eax = 0`); no computation on the result. |
| `0x512bda0` (33 bytes) | Call then tail-jump with a reloaded argument; no computation on the result. |
| `0x5459700` / `0x5459740` (58 bytes each) | Near-identical twin pair: call, `xchg` the result into a slot, then zero object fields. A real effect, but the pair structure and multi-effect rule are weaker than the selected singleton gate. |

## Limits

- The callee's behavior is excluded; only its identity and extent are
  locked. The rule therefore says what the window does with the
  returned object, not what the callee computes.
- The window's return value is the incoming `rax` (restored by
  `pop rax`); the stored field is its only observable effect.
- The gate depends on `inc` setting ZF: there is no separate comparison
  instruction, and no other instruction between `inc` and `cmovne`
  touches the flags (`mov` does not affect flags).
- Nearest-symbol annotations from the disassembler carry large offsets
  and are not identifications; no symbol name is claimed.
- The zero-caller claim covers direct `e8` calls in `.text` only.

## Checker and tests

Reproduce from the repository root:

```
python3 tools/foundation_sentinel_increment.py \
  --check research/work-items/foundation-sentinel-increment-94/evidence.json
python3 -m unittest tests.test_foundation_sentinel_increment -v
```

The checker re-derives the window body, its padding, the five retained
FDE records, the callee body and padding, the call encoding, the
sentinel-increment rule on its edges, the callee's single direct call
site, and the zero-caller scan from target bytes. The unit tests run
the checker on the real evidence plus corruption controls: each control
mutates one recorded fact (body hash, padding, target digest, call
target, gate instructions, store field, FDE offsets, callee hash/extent/
padding/call sites, caller list, edge values) and must make the checker
fail.

## Why this packet

The window is a complete, self-contained computation in 30 bytes: one
call, one sentinel-guarded increment, one store, one return. Its shape
is unique among small single-call windows, its closest claimed relative
scores 0.133, and its callee is called from nowhere else. The gate is
not a separate comparison bolted on: it falls out of the `inc`
instruction's own flags, which is what makes the window directly
readable rather than merely short.

## Files

- `README.md` (this file)
- `evidence.json`
- `window.objdump.txt` (GNU disassembly of the window and the callee,
  including their padding)
- `frames.txt` (FDE excerpts for the window, the next FDE, the previous
  FDE, the callee, and the FDE after the callee)
- `MANIFEST.sha256`
- `tools/foundation_sentinel_increment.py`
- `tests/test_foundation_sentinel_increment.py`
