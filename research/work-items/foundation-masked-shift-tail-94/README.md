# Foundation masked-shift tail helper (node #94)

A 57-byte single-call window at `0x4f9bfa0` that calls `0x5423270` with
two words loaded from its second argument, then tail-jumps to `0x4f9bee0`
with a computed first argument: the callee's return value, masked by a
field of the object, shifted left by 8, and added to a base field of the
object. It is one small, directly readable window: no branch, no loop, no
flag test, no constant pool, and no second call. The callee's behavior is
excluded from the rule; only its identity and extent are locked.

## Rule

Call `0x5423270` with `rdi = qword[arg2]` and `rsi = qword[arg2+8]`,
then tail-jump to `0x4f9bee0` with `rdi = ((eax & dword[obj+0x40]) << 8)
+ qword[obj+0x78]`, `rsi` restored to the original second argument, and
`rdx = eax` (the callee's return value, passed through).

In other words: the window turns the callee's return value into a slot
address — a base plus 256 times the masked value — and forwards the
original second argument and the raw return value alongside it. The mask
is a 32-bit field, so bits of `eax` above the mask are discarded; the
shift is a 64-bit shift of the zero-extended 32-bit masked value, so no
sign extension occurs.

## Window

| Field | Value |
| --- | --- |
| Start | `0x4f9bfa0` |
| End (exclusive) | `0x4f9bfd9` |
| Size | 57 bytes |
| FDE section offset | `0x0028a96c` |
| FDE CIE | `0x00000000` |
| Padding | 7 bytes `cc` (int3) to the next FDE at `0x4f9bfe0` |
| Body SHA-256 | `03d6fc0294b730977b7493eca14f7cde9215691f0a22a57113483621974ce61d` |
| Target | node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Worktree HEAD | `2993e46` |

Instruction walk, in order:

| Address | Instruction | Role |
| --- | --- | --- |
| `0x4f9bfa0` | `endbr64` | Entry marker |
| `0x4f9bfa4` | `push rbp` | Save callee-saved register |
| `0x4f9bfa5` | `mov rbp, rdi` | Keep the object pointer |
| `0x4f9bfa8` | `push rbx` | Save callee-saved register |
| `0x4f9bfa9` | `mov rbx, rsi` | Keep the second argument |
| `0x4f9bfac` | `sub rsp, 8` | Stack alignment |
| `0x4f9bfb0` | `mov rdi, [rbx]` | First callee argument |
| `0x4f9bfb3` | `mov rsi, [rsi+8]` | Second callee argument |
| `0x4f9bfb7` | `call 0x5423270` | The single call |
| `0x4f9bfbc` | `mov rsi, rbx` | Restore the original second argument |
| `0x4f9bfbf` | `mov edi, eax` | Copy the return value (32-bit) |
| `0x4f9bfc1` | `and edi, [rbp+0x40]` | Mask it with the object's mask field |
| `0x4f9bfc4` | `mov edx, eax` | Pass the raw return value through |
| `0x4f9bfc6` | `shl rdi, 8` | Scale the masked value by 256 |
| `0x4f9bfca` | `add rdi, [rbp+0x78]` | Add the object's base field |
| `0x4f9bfce` | `add rsp, 8` | Restore the stack |
| `0x4f9bfd2` | `pop rbx` | Restore |
| `0x4f9bfd3` | `pop rbp` | Restore |
| `0x4f9bfd4` | `jmp 0x4f9bee0` | Tail jump; the window has no `ret` |

The window ends with a tail jump, not a `ret`, so its FDE range and
padding must not be described as ret-terminated. The jump target
`0x4f9bee0` is itself an FDE start (`0x4f9bee0..0x4f9bf94`, section
offset `0x006215a8`, CIE `0x006205d0`); its behavior is excluded, only
its identity is locked.

## Callee

| Field | Value |
| --- | --- |
| Start | `0x5423270` (an FDE start) |
| End (exclusive) | `0x5423589` |
| Size | 793 bytes |
| FDE section offset | `0x002ba164` |
| FDE CIE | `0x00000000` |
| Padding | 7 bytes `cc` to the next FDE at `0x5423590` |
| Body SHA-256 | `6fd05d2fca8e456ae975dda233b8ae45eec53585862ad8d64f05a17ad94c7a49` |

The callee is called from 18 direct sites in `.text`, including this
window (`0x4f9bfb7`); the full list is recorded in `evidence.json` and
re-derived by the checker. Only two of those sites sit inside small
single-call windows: this window and the 146-byte `0x5169380`, whose
imul-chain rule is unrelated, so the shared callee is not a shared rule.
Because the callee is 793 bytes, its body is locked by length, SHA-256
and padding rather than by locking every one of its instructions; that
locks its identity and extent, which is all the rule uses.

## Neighbors

| FDE start | Size | Relation |
| --- | --- | --- |
| `0x4f9bee0` | 180 bytes | The tail-jump target (above) |
| `0x4f9bfe0` | 270 bytes | Next FDE after the window |
| `0x5423270` | 793 bytes | The callee (above) |
| `0x5423590` | 16 bytes | FDE after the callee |

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x4f9bfa0`
finds exactly zero sites, so this packet has seven files (no
`caller.objdump.txt`). Register-indirect references, other pointer paths,
prefixes, and data sections are not a complete xref census, so the claim
is scoped to direct `e8` calls, not to all possible references.

## Twins and uniqueness

Claimed-body byte comparison against the previously claimed windows
(#123–#150) gives a maximum similarity of 0.211 on the max-length
measure and 0.235 on the min-length measure (both against #137), well
below the 0.60 cutoff. Against the full corpus of single-call FDE
windows, the best non-self matches are 0.333 on the max-length measure
(at `0x5524370`, 46 bytes: a lea/sub/add window calling a different
callee) and 0.439 on the min-length measure with the 20-byte substance
floor (at `0x5432e30`, 41 bytes: an argument-shuffling tail jump that
forwards the return value unchanged and computes nothing). The window's
mnemonic skeleton (`endbr64 push mov push mov sub mov mov call mov mov
and mov shl add add pop pop jmp`) is a singleton among 31,898
single-call FDE windows of 20-150 bytes. Its nearest claimed relative
is #137; its nearest corpus bodies compute or forward something else.

## Rule edges

| eax | mask | base | Model | Out |
| --- | --- | --- | --- | --- |
| `0x1234` | `0x000000ff` | `0x1000` | `0x34 << 8 = 0x3400`, `+ 0x1000` | `0x4400` |
| `0xffffffff` | `0xffffffff` | `0x0` | Full mask: value shifted to `0xffffffff00` | `0xffffffff00` |
| `0x100` | `0x0000000f` | `0x2000` | Masked value is zero, base passes through | `0x2000` |
| `0x00000001` | `0x00000001` | `0x0` | Single bit shifted to `0x100` | `0x100` |
| `0x12345678` | `0x0000ff00` | `0x10` | `0x5600 << 8 = 0x560000`, `+ 0x10` | `0x560010` |
| `0x80000000` | `0xffffffff` | `0x0` | High bit set: 64-bit shift, no sign extension | `0x8000000000` |

The edges are model checks on the recorded arithmetic, not executions
of the target binary. Bits of `eax` outside the mask never reach the
shift, and the shift never sign-extends because the masked value is
32-bit before the 64-bit shift.

## Rejected candidates

| Address | Reason |
| --- | --- |
| `0x521b5a0` (24 bytes) | Genuine bit-extract (`shr 4; and 1` after the call) but thinner than the chosen window; held as a backup, not claimed here. |
| `0x53a7fc0`, `0x539d930`, `0x5432680` (22–24 bytes) | Bare sub/call/add/add/ret wrappers in the same thin family as #150's rejected `0x53a7fa0`: no computation worth a standalone packet. |
| `0x5542a10` (31 bytes) | Thunk: loads a static address, calls, zeroes `edi`, tail-jumps. The window itself computes nothing; its content lives in the excluded endpoints. |
| `0x5173a60` (40 bytes) | Argument-forwarding adapter: one call, then a tail jump with reshuffled arguments and a zeroed third argument. Weaker than the chosen mask/shift computation. |
| `0x5160ef0` (36 bytes) | Stores a constant global address to `[obj]` and then calls; the store is not a computation over the call's result. |
| `0x5285820`, `0x5285ad0` | Killed-family neg/sbb pair, do-not-build. |
| `0x5520e80` | Opaque, do-not-build. |
| 0x5660440 family (76/88/92 bytes) | Identical skeletons across many sites calling one callee: a shared template population, not a standalone window. |

## Limits

- The callee's behavior and the tail-jump target's behavior are excluded;
  only their identities and extents are locked. The rule therefore says
  what the window computes and where it goes, not what either endpoint
  does with the arguments.
- The mask is 32-bit and the shift is 64-bit on the zero-extended masked
  value; a high-bit return value does not sign-extend.
- The window has no `ret`: control leaves by tail jump, and the
  computed first argument is the window's only new value in this packet.
- Nearest-symbol annotations from the disassembler carry large offsets
  and are not identifications; no symbol name is claimed.
- The zero-caller claim covers direct `e8` calls in `.text` only.

## Checker and tests

Reproduce from the repository root:

```
python3 tools/foundation_masked_shift_tail.py \
  --check research/work-items/foundation-masked-shift-tail-94/evidence.json
python3 -m unittest tests.test_foundation_masked_shift_tail -v
```

The checker re-derives the window body, its padding, the five retained
FDE records, the callee body and padding, the callee's 18 direct call
sites, the call and tail-jump encodings, the masked-shift rule on its
edges, and the zero-caller scan from target bytes. The unit tests run
the checker on the real evidence plus corruption controls: each control
mutates one recorded fact (body hash, padding, target digest, call
target, jump target, FDE offsets, callee hash/extent/padding, callee
call-site list, caller list, edge values, mask/base fields) and must
make the checker fail.

## Why this packet

The window is a complete, self-contained computation in 57 bytes: one
call, one mask, one shift, one add, one tail jump. Its shape is unique
among small single-call windows, its closest claimed relative scores
0.211, and its closest corpus bodies compute something else or nothing
at all. The shared callee and its 18 call sites are disclosed, not
hidden: many callers share the callee, but only this window computes
the masked slot address.

## Files

- `README.md` (this file)
- `evidence.json`
- `window.objdump.txt` (GNU disassembly of the callee and the window,
  including their padding)
- `frames.txt` (FDE excerpts for the window, the next FDE, the callee,
  the FDE after the callee, and the tail-jump target)
- `MANIFEST.sha256`
- `tools/foundation_masked_shift_tail.py`
- `tests/test_foundation_masked_shift_tail.py`
