# Foundation nonzero-flag helper (node #94)

An 88-byte single-call window at `0x5650a60` that derives a nonzero
flag from its 32-bit second argument with a bit trick, then applies one
shared callee to two fields of its object: it calls `0x5656fc0` with
`(obj+0x60, obj+0x60, flag, 0x918940)` and tail-jumps to the same
callee with `(obj+0x90, obj+0x90, flag, 0x918940)`. One flag derivation,
one call, one tail jump: no branch, no loop, no second distinct callee.
The callee's behavior is excluded from the rule; only its identity and
extent are locked.

## Rule

Let `n = movsxd(esi)` (the 32-bit second argument, sign-extended to 64
bits) and `flag = (n != 0) ? 1 : 0`. Then:

1. Call `0x5656fc0` with `rdi = obj+0x60`, `rsi = obj+0x60`,
   `rdx = flag`, `rcx = 0x918940`.
2. Tail-jump to `0x5656fc0` with `rdi = obj+0x90`, `rsi = obj+0x90`,
   `rdx = flag`, `rcx = 0x918940`.

The flag is derived before the calls and feeds both of them. That
ordering is disclosed, not hidden: the derivation is a genuine
computation (a new boolean from the input), not argument shuffling —
every shuffle-only candidate found in this hunt was rejected below.

## The bit trick

The window computes the flag as

```
rbx = 1 ^ (((~n) & (n - 1)) >> 63)
```

Proof that this equals `(n != 0)`: bit 63 of `~n` is 1 exactly when
`n >= 0`; bit 63 of `n - 1` is 1 exactly when `n <= 0` (n is 32-bit
sign-extended, so `n - 1` cannot overflow the sign bit); their AND
therefore has bit 63 set exactly when `n == 0`. Shifting right by 63
yields 1 exactly for `n == 0` and 0 otherwise, and `xor 1` flips it to
the nonzero flag. The intermediate `mov` instructions between the
arithmetic steps do not touch the flags, and no comparison instruction
is involved.

## Window

| Field | Value |
| --- | --- |
| Start | `0x5650a60` |
| End (exclusive) | `0x5650ab8` |
| Size | 88 bytes |
| FDE section offset | `0x002daa20` |
| FDE CIE | `0x00000000` |
| Padding | 8 bytes `cc` (int3) to the next FDE at `0x5650ac0` |
| Body SHA-256 | `1145fa7fac82339f9c35b0c7884497a01fbdb551e9d2cbeda2e766e062190c66` |
| Target | node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Worktree HEAD | `2993e46` |

Instruction walk, in order:

| Address | Instruction | Role |
| --- | --- | --- |
| `0x5650a60` | `endbr64` | Entry marker |
| `0x5650a64` | `movsxd rsi, esi` | Sign-extend the 32-bit input to `n` |
| `0x5650a67` | `push r12` | Save callee-saved register |
| `0x5650a69` | `mov rdx, rsi` | Copy `n` |
| `0x5650a6c` | `sub rsi, 1` | `n - 1` |
| `0x5650a70` | `push rbp` | Save callee-saved register |
| `0x5650a71` | `mov rbp, rdi` | Keep the object pointer |
| `0x5650a74` | `not rdx` | `~n` |
| `0x5650a77` | `push rbx` | Save callee-saved register |
| `0x5650a78` | `and rdx, rsi` | `~n & (n - 1)` |
| `0x5650a7b` | `shr rdx, 63` | Isolate bit 63: 1 exactly when `n == 0` |
| `0x5650a7f` | `lea r12, [rip-0x4d38146]` | Fixed `.rodata` address `0x918940` |
| `0x5650a86` | `mov rbx, rdx` | Keep the bit |
| `0x5650a89` | `lea rdi, [rdi+0x60]` | First field pointer |
| `0x5650a8d` | `xor rbx, 1` | The nonzero flag |
| `0x5650a91` | `mov rsi, rdi` | First field pointer, second argument |
| `0x5650a94` | `mov rcx, r12` | Table address |
| `0x5650a97` | `mov rdx, rbx` | Flag |
| `0x5650a9a` | `call 0x5656fc0` | The single call |
| `0x5650a9f` | `lea rdi, [rbp+0x90]` | Second field pointer |
| `0x5650aa6` | `mov rcx, r12` | Table address |
| `0x5650aa9` | `mov rdx, rbx` | Flag |
| `0x5650aac` | `mov rsi, rdi` | Second field pointer, second argument |
| `0x5650aaf` | `pop rbx` | Restore |
| `0x5650ab0` | `pop rbp` | Restore |
| `0x5650ab1` | `pop r12` | Restore |
| `0x5650ab3` | `jmp 0x5656fc0` | Tail jump to the same callee; no `ret` |

The tail-jump target is the callee itself, so the window's two
invocations share one rule: same callee, same flag, same table, two
field pointers.

## Callee

| Field | Value |
| --- | --- |
| Start | `0x5656fc0` (an FDE start) |
| End (exclusive) | `0x5657099` |
| Size | 217 bytes |
| FDE section offset | `0x002db3d4` |
| FDE CIE | `0x00000000` |
| Padding | 7 bytes `90 66 0f 1f 44 00 00` (NOP padding, not int3) to the next FDE at `0x56570a0` |
| Body SHA-256 | `a160770fd4eb9469f74171b2863edc15b6e3e73373e354602155535cd006d2ca` |

The callee is called from 47 direct sites in `.text`, including this
window (`0x5650a9a`); the full list is recorded in `evidence.json`
and re-derived by the checker. The other 46 sites sit inside larger
functions, and no other small single-call window calls this callee, so
the shared callee is not a shared rule — but the sharing is disclosed,
not hidden. The callee's behavior is excluded from the rule either way.

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x5650a60`
finds exactly one site, at `0x5640d6d` inside the 453-byte function
`0x5640cd0..0x5640e95` (FDE offset `0x002d8c50`, CIE `0x00000000`),
recorded in `caller.objdump.txt`. So this packet has eight files (one
caller file). Register-indirect references, other pointer paths,
prefixes, and data sections are not a complete xref census.

## Twins and uniqueness

Raw FDE bytes, position-wise equal bytes, no normalization. Two
claimed cohorts: A = claimed windows present in the 20–150B
single-call census; B = every claimed window from every `evidence.json`
in prior worktrees and the main tree (the comprehensive set, including
#150–#153).

- Against claimed windows: maximum similarity 0.122 max-length
  (cohorts A and B agree, at `0x52f2b50`), well below the 0.60 cutoff.
- Against the full corpus of 31,898 single-call FDE windows: best
  non-self 0.159 max-length (at `0x544ce30`) and 0.304 min-length with
  the 20-byte floor (at `0x5164790`).
- The mnemonic skeleton is a singleton among 31,898 single-call FDE
  windows of 20-150 bytes, and this window is the only single-call
  census window calling `0x5656fc0`.
- Measure validation: the same procedure reproduces #152's
  claimed-best 0.250 max-length and corpus-best 0.438 / 0.500,
  #151's claimed-best 0.211 max / 0.235 min and corpus-best 0.333 /
  0.439, and #153's claimed-best 0.133 max and corpus-best 0.167 /
  0.200 exactly.

## Rule edges

| esi (32-bit) | n (sign-extended) | flag |
| --- | --- | --- |
| `0x00000000` | `0x0` | `0x0` (zero input) |
| `0x00000001` | `0x1` | `0x1` |
| `0xffffffff` | `-0x1` | `0x1` |
| `0x7fffffff` | `0x7fffffff` | `0x1` (largest positive int32) |
| `0x80000000` | `-0x80000000` | `0x1` (smallest int32) |

Edges are model checks on the recorded arithmetic (both the direct
nonzero test and the bit-trick identity), not executions of the target
binary.

## Rejected candidates

| Address | Reason |
| --- | --- |
| `0x5317380` (46B) | strlen + string-replace tail jump; call result only forwarded as an argument, no own computation. |
| `0x522b730` / `0x5432e30` / `0x4ff1e00` / `0x5488da0` | Argument-shuffling tail jumps; call result discarded or forwarded unchanged. |
| `0x4fa8540` (45B) | `_M_assign` call followed by field zeroing; the call result is discarded (`xor eax, eax`). |
| `0x5423780` / `0x54237b0` (35B) | Store-pair twins; post-call `rdx` value depends on excluded callee behavior, so the rule is murky. |
| `0x5240b50` / `0x5335850` (20B) | gettid-style `cltq` wrappers; thin, and a twin pair (same skeleton, different callees). |
| `0x52dc0f0` (20B) | Call with a loaded argument and no post-call computation. |
| `0x5459780` (63B) | `xchg` + field-zeroing family (same pattern as rejected `0x5459700`/`0x5459740`); mixed effects. |
| `0x54d9090` (38B) | Flag-OR gate whose call result is discarded (`xor eax, eax`); boolean-only return. |
| `0x54e2640` (46B) | Two-path window gated on a global byte; global-dependent rule, branchy, weaker than the chosen window. |
| `0x5088b00` (67B) | Conditional store fragment with two stores and a branch; mid-function shape, mixed effects. |
| `0x543bde0` (59B) | malloc align + pad-byte store + field zeroing; mixed effects and a branch. |
| `0x543be20` family (35B) | free-wrapper population (four near-identical siblings calling `free@plt`). |
| `0x521b5a0` (24B) | Genuine bit-extract (`shr 4; and 1`) but too thin for a standalone packet; remains unclaimed behind this window. |

## Limits

- The callee's behavior is excluded; only its identity and extent are
  locked. The rule therefore says what the window computes and which
  function it applies twice, not what that function does.
- The flag derivation happens before the calls and is shared by both;
  it is a real derivation (proved above), not a shuffle.
- The `0x918940` table address is a fixed `.rodata` constant; its
  contents are not identified and play no role beyond the constant.
- The window has no `ret`: control leaves by tail jump to the callee.
- Nearest-symbol annotations carry large offsets and are not
  identifications; no symbol name is claimed.
- The caller claim covers direct `e8` calls in `.text` only.

## Checker and tests

Reproduce from the repository root:

```
python3 tools/foundation_nonzero_flag.py \
  --check research/work-items/foundation-nonzero-flag-94/evidence.json
python3 -m unittest tests.test_foundation_nonzero_flag -v
```

The checker re-derives the window body, its padding, the six retained
FDE records, the callee body and its NOP padding, the call and
tail-jump encodings, the table address, the nonzero-flag rule (both the
direct test and the bit-trick identity) on its edges, the single direct
caller, and the full 47-site callee call list from target bytes. The
unit tests run the checker on the real evidence plus corruption
controls: each control mutates one recorded fact (body hash, padding,
target digest, call target, jump target, table address, FDE offsets,
callee hash/extent/padding, caller list, callee call list, edge values)
and must make the checker fail.

## Files

- `README.md` (this file)
- `evidence.json`
- `window.objdump.txt` (GNU disassembly of the window and the callee,
  including their padding)
- `caller.objdump.txt` (GNU disassembly of the caller function)
- `frames.txt` (FDE excerpts for the window, the next FDE, the previous
  FDE, the callee, the FDE after the callee, and the caller)
- `MANIFEST.sha256`
- `tools/foundation_nonzero_flag.py`
- `tests/test_foundation_nonzero_flag.py`
