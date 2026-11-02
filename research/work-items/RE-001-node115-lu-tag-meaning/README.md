# RE-001: what the node #115 lu.rs tag 1 vs 3 means — the "compare helper" is Tokio time code, not a comparison

- Component: `base/src/lu.rs` conversion tags, answered through the callee at `0x5cf2d30`.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #183 (PR #2106, open) left open whether the helper at `0x5cf2d30`
  decides tag 1 vs 3 by value-equality or by identity. Answer: **neither**.
  The helper performs no comparison of two values and no comparison of two
  pointers. It returns false exactly when the output struct is in the
  empty/reset state (`[+0x38] == -1` and `[+0x58] == 0`), true otherwise.
  In the conversion, helper-false takes the drop path and stores tag 1;
  helper-true skips the drop path and stores tag 3. So **tag 1 = empty state,
  tag 3 = set state** — not equal vs different, not same vs different object.
- Correction to #183, stated precisely: #183's mechanism stands (the drop path
  precedes tag 1; tag 3 skips the drop). Its gloss does not: the callee is not
  a "compare helper" and its boolean is not an equality verdict. This packet
  replaces that gloss with the mechanism below, and cites #183 (PR #2106) as the
  inviting prior packet. #183's claimed conversion body (`0x15d5cb0..0x15d606b`)
  is cited, not re-claimed; the new bytes claimed here are the helper body only.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| helper (characterized) | `0x5cf2d30..0x5cf2fef` | 703 | 165 |
| conversion call-site excerpt (cited from #183, not claimed) | `0x15d5f37..0x15d5f8e` | 87 | — |

The helper FDE is at `.eh_frame` section offset `0x72d65c` (length `0x4c`),
CIE `0x39672c` (`zPLR`). The common return is at `0x5cf2f06`, `ret` at
`0x5cf2f14`. The landing pad at `0x5cf2f63..0x5cf2fe9` lies inside the FDE.
Body SHA-256 `fb3fb193f0b14f251e01da509c670d299323482419d1edef4170d948604cbbb2`
(capstone linear disassembly, 165 instructions). All bodies are hash-pinned
without normalization.

## The return condition (the whole answer)

The helper takes `(rdi = struct pointer, rsi = context pointer)`. Its second
argument is dereferenced once at entry (`mov rsi, [rsi]`) and that value is used
only on one path (see below); it is never compared to anything. Every
comparison in the body is against a constant, a TLS state byte/word, or a field
of the single struct at `rdi`. The complete return inventory:

- FALSE, exactly one path: at `0x5cf2e9e` the helper loads `[r14+0x38]` and
  compares it to `-1`; if equal, at `0x5cf2ee7` it loads the byte `[r14+0x58]`;
  if that byte is zero, at `0x5cf2ef0` it executes `xor eax, eax` and returns
  false. No other instruction writes zero to the return register.
- TRUE, every other non-panic path: if `[r14+0x38] != -1`, the helper sets
  `al = 1` (at `0x5cf2ea7` or via the TLS-state paths at `0x5cf2ed4`/`0x5cf2f04`)
  and returns true. If `[r14+0x38] == -1` but `[r14+0x58] != 0`, control reaches
  the landing-pad panic path (`0x5cf2f63`, citing `sleep.rs:467:23`); it does
  not return.
- Panic paths (no return): the `10^9` validation and the nonzero-byte check
  below, plus the landing-pad path above.

In conversion coordinates the helper's first argument is `[rbx+0x18]`
(`r14 = rbx + 0x18` at the call site), so the false condition reads
`[rbx+0x50] == -1` and `[rbx+0x70] == 0`.

## Why false means "empty": the helper writes that state itself

When `[r14+0x10] == 2`, the helper runs a reset: it manipulates a refcount
(`lock xadd` on `[r14+0x8]`, drop helper `0x5cf1d70` on `[r14+0x10]`), then
writes the empty template over `[r14+0x10..0x58]`: `[+0x10] = r13`,
`[+0x18] = old [+0x8]`, zeros at `[+0x20..0x2f]`, `[+0x30] = 0`,
**`[+0x38] = -1`**, `[+0x40] = 0`, `[+0x50] = 0`, **`[+0x58] = 0`**, then calls
`0x5cead40` with (`[r14+0x10]`, `[r14+0x60]`, `[r14+0x68]`). The false
condition checks exactly two of the template's sentinel fields
(`+0x38 == -1`, `+0x58 == 0`). The helper therefore returns false exactly
when the struct matches the empty state it itself writes — a state check, not
a comparison between two values.

## The conversion direction (verified at the call site)

At the conversion call site (`0x15d5f37..0x15d5f8e`, bytes cited from #183's
claimed body, hash-pinned in `records.json`):

- `0x15d5f37`: `lea r12, [rbx+0x18]`; `rdi = r12`; `rsi = r15` (the
  conversion's second argument, passed through untouched from its callers).
- `0x15d5f41`: indirect call through GOT slot `0x64e0858` → `0x5cf2d30`.
- `0x15d5f47`: `mov r15b, 0x3` (default tag 3).
- `0x15d5f4a`: `test al, al`; `0x15d5f4c`: `jne 0x15d5f8a` — helper-true
  skips the drop path.
- `0x15d5f4e..0x15d5f83`: helper-false path: `lock dec` on `[rbx+0x20]` with a
  drop call, then `call 0x15df190` on `[rbx+0x28]`, then `mov r15b, 0x1`.
- `0x15d5f8a..0x15d5f8e`: store `r15b` to `[r13]` and to `[rbx+0x90]`.

So: helper-false → drop path → tag 1; helper-true → skip drop → tag 3.
Combined with the return condition: tag 1 = empty state, tag 3 = set state.

## The helper is Tokio time code, not lu.rs logic

Three panic Location records, resolved through RELATIVE relocation addends
(the file-pointer slots in `.data.rel.ro` are zero; the addend is authoritative):

| Site | Location | Evidence |
| --- | --- | --- |
| `10^9` validation panic (`0x5cf2f15`) | `tokio/src/runtime/time/entry.rs:549:30` | message (115 bytes, `.rodata` `0x94ca6b`): "A Tokio 1.x context was found, but timers are disabled. Call `enable_time` on the runtime builder to enable timers." |
| nonzero-byte panic (`0x5cf2f30`) | `tokio/src/runtime/time/entry.rs:539:9` | format fragment "`\rtimer error: `" (`.rodata` `0x433ed3`) |
| landing-pad panic (`0x5cf2f63`) | `tokio/src/time/sleep.rs:467:23` | — |

Full vendored paths are in `records.json`
(`/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/...`). The helper is shared,
not lu-specific: 27 indirect call sites in the binary reach it through GOT slot
`0x64e0858` (full list in `records.json`), including the conversion's site and
sites inside #183's sibling instances (`0x2a90ce1`, `0x2c7f5f1`). It has zero
direct `E8` callers. No dbstkddl8-create topic, address, table, or model is used.

## Observed structure (context, not the main claim)

- TLS lazy init: `r15 = -0x130`; state byte at `fs:[-0xe8]`, word at
  `fs:[-0xec]`, byte at `fs:[-0xeb]`. State `0` calls init `0x5ca0d20` with
  (TLS base, `0x5cdf410`); state `2` skips the word block; state `1` proceeds.
  The TLS word's low bit and second byte steer the `0x5cf2ef4` path, which
  calls `0x5cf3b90` with (dereferenced second argument, `0x64c6648` → Tokio
  path string `.../tokio/src/task/coop/mod.rs` via RELATIVE addend).
- `10^9` validation: `rcx = [r14+0x18]`; offset `0x160` or `0x240` selected by
  the low bit of `[r14+0x10]`; if `DWORD [rcx+offset+0x90] == 0x3b9aca00`
  (1,000,000,000) the helper panics at `entry.rs:549:30`; if the byte at
  `[rcx+offset+0x80]` is nonzero it panics at `entry.rs:539:9`. A field drop
  (`0x5ce91b0` on `[r14+0x40]`) follows the checks.
- Indirect targets (mapped as call targets only, not decoded): TLS init
  `0x5ca0d20` (255B), field drop `0x5ce91b0` (769B), coop-path callee
  `0x5cf3b90` (162B), panic `0x1680bd0` (52B), panic_fmt `0x1680e80` (44B),
  landing-pad cleanup `0x1680cab` (20B). Direct callees: `0x5cf1d70` (136B),
  `0x5cf1d10` (85B), `0x5cead40` (309B), plus the passed function pointer
  `0x5cdf410` (71B) and thunk `0x5cdf610` (19B) in panic arguments.

## What this does not claim

- The Rust function name of `0x5cf2d30` is not asserted (no source in tree);
  "Tokio time code" rests on the three vendored Location records plus the Tokio
  panic strings, not on a symbol name.
- The identity of the helper's second argument (the conversion's passed-through
  context pointer) is unresolved beyond its single dereference and its use on
  the `0x5cf2ef4` path.
- The TLS slot layout's Tokio-internal meaning (which handle/cell the `-0xe8`
  state byte belongs to) is not decoded; only the state machine's observable
  transitions are claimed.
- The `0x160`/`0x240` offset selection's variant meaning is not decoded; only
  the low-bit selection and the two validation checks are claimed.
- No gate is requested by this packet; the next question is what the
  conversion's passed-through context pointer points to, and what the
  `0x5cf3b90` coop-path call does with it.
