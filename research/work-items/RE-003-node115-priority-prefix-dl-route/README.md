# RE-003: the `dl` route of the node #115 priority-prefix bin decoders — who can set it, and what the alternate does

- Component: serialization/foundation, delayed-action configuration — the
  route flag of the MessagePack decoders certified by
  `RE-003-node115-priority-prefix-caller`.
- Target: node **#115**, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Bounded questions: (1) which callers can deliver `dl != 0` to the three
  bin decoders, i.e. is the alternate route reachable at all as wired;
  (2) what the alternate function (`0x2b87440` for caller A) does with the
  slice it receives instead of the byte-fed entry.
- Observation/proof: a complete static reference census (below) shows each
  decoder FDE is referenced **only** by its two parent `E8` call sites,
  and every one of those sites passes `rdx = 0` — so no censused caller
  can set `dl != 0` and the alternate route is unreachable from any static
  caller in this binary. The alternate itself, traced end to end (126
  bytes), does **not** call the byte-fed entry and does **not** parse the
  payload: it stores the slice `{pointer, length}` under discriminant
  byte `6` in a stack descriptor, calls a 154-byte helper with the shared
  message piece at `0x44f07a` (legible fragments `invalid type: ` /
  `, expected `), writes qword `2` at the output base — the same result
  tag the decoder's own short-payload error record uses — and returns.
- No decoder semantics beyond the pinned route facts, no concrete Rust
  type for the descriptor, and no reconstruction gate is claimed.

## Why this item, in one paragraph

The operator action is unchanged from the caller packet: a delayed-action
configuration reaches the node in MessagePack form with the delay
parameters as one bin field. The basis for the expected behaviour is the
caller packet (#2442), which pinned the `dl` split in each decoder's
shared tail, certified that both parent call sites pass `rdx = 0`, and
left the explicit next questions "which input, if any, reaches the bin
supply with `dl != 0` — and what does the alternate slice decoder
(`0x2b87440` for caller A) make of the same payload?" The loss if this
stays unrecorded: a reimplementation must guess whether the `dl != 0`
route is a live second input path (needing its own decoder) or dead
wiring, and what the alternate produces — the bytes show it is an
error-producing route that is unreachable from every static caller, a
contract recorded nowhere else. The item is independent of the nearest
open RE-003 PRs by repro case, not just by filename: #2329 is a
protocol-design document with no binary trace, and #2393/#2075/#2062 are
robustness fixes to the `priority_prefix_static` checker tool; none of
them censuses a caller or traces the alternate.

## Evidence identity and completeness

| Role | FDE half-open VA range | Bytes | Retention |
| --- | --- | ---: | --- |
| alternate A (owner) | `0x2b87440..0x2b874be` | 126 | full export + hash + frames |
| alternate B (owner) | `0x3b9c8a0..0x3b9c91e` | 126 | full export + hash + frames |
| alternate C (owner) | `0x54552c0..0x545533e` | 126 | full export + hash + frames |
| caller A/B/C (boundary, #2442) | `0x1a63db0…`, `0x33210f0…`, `0x4adf150…` | 6,125 each | hash + pinned windows |
| parent A/B/C (boundary, #2442) | `0x19271c0…`, `0x32e15c0…`, `0x4b76720…` | 8,435 each | hash + call-site pins |
| helper A/B/C (boundary) | `0x18be120…`, `0x3046740…`, `0x4892290…` | 154 each | hash + write pins |
| dispatch shims ×3 (boundary) | `0x2d49fb0…`, `0x452a050…`, `0x57a6f70…` | 16 each | hash (bodies identical) |
| descriptor fn / gate fn / helper slot fn (boundary) | `0x5c4f380…` / `0x16815e0…` / `0x141e3a0…` | 705 / 503 / 408 | hash + slot binding |

The measured denominator for the census is the whole `.text`
(83,719,936 bytes) plus `.rela.dyn` and a whole-capture raw scan; for the
alternate trace it is the three complete alternate FDEs (378 bytes,
retained in full). The three alternates are byte-identical after masking
the five displacement fields (data address, descriptor slot load,
dispatch-shim address, message-piece address, helper call); every masked
field is checked relationally per sibling. Boundary body hashes are
re-derived here and match the owning packets' `records.json` values
exactly where those exist. `records.json` retains body hashes, file
offsets and actual FDE/CIE raw bytes for all eighteen functions;
`frames.txt` contains independent GNU readelf confirmations. No
normalization mask is applied to any retained body.

## Part 1 — the reference census and the `dl` verdict

Reference kinds censused for each of the six starts (three decoders,
three alternates), over the whole capture:

| Kind | Decoders (each) | Alternates (each) |
| --- | --- | --- |
| `E8` call sites | **2, both in the own parent FDE** | **2, both in the own decoder FDE** |
| `E9` jumps | 0 | 0 |
| `EB` rel8 jumps | 0 | 0 |
| `0f 8x` conditional jumps | 0 | 0 |
| RIP-relative refs (`ff 15`/`ff 25`, REX.W `lea`/`mov`) | 0 | 0 |
| `.rela.dyn` addends naming the start | 0 | 0 |
| Raw 8-byte occurrences anywhere | 0 | 0 |
| Raw 4-byte occurrences | 0 (A, C); 1 (B, explained) | 0 |
| Bytes before the start | int3 gap of 7 / 6 / 3 | int3 gap of 2 / 2 / 2 |

The single raw 4-byte occurrence (of caller B's start) is the
`initial_location` pcrel delta inside the `.eh_frame` FDE record at
section offset `0x1d3500` (range `0x419b4d0..0x419b640`):
`0x419b4d0 − 0xe7a3e0 = 0x33210f0` — unwind arithmetic that numerically
equals the decoder start, verified as an identity by the checker, not a
code or data reference. The int3 gaps exclude fall-through entry from
the preceding FDE.

Parent wiring is re-derived from the pinned capture: each parent body
contains exactly the two recorded call sites to its decoder, and the
five bytes before every site are `4c 89 f6 31 d2` (`mov rsi, r14` /
`xor edx, edx`). Combined with the caller packet's pinned trace — in
which the shared tail's `test dl, dl` at decoder `+0xe67` reads the
entry `dl` — the verdict is:

**Every static entry into the three decoders passes `rdx = 0`. The
`dl != 0` route has no enabling caller in this binary.** What could set
`dl` nonzero is therefore: nothing that statically references the
decoders. The residual channels a census cannot enumerate (an address
computed arithmetically into a register, a base-plus-offset jump table)
are stated in Limits.

The alternates' own census has one new fact beyond the caller packet:
each alternate has **two** call sites in its decoder, not one. The
second site (decoder `+0x1066`) is pinned in Part 2.

## Part 2 — what the alternate does with the slice

The decoder's `dl != 0` block (decoder `+0x113c`, pinned in #2442) calls
the alternate with the same slice the entry route would have consumed:
`rdi` = the output struct, `rsi` = payload start `p`, `rdx` = declared
length `L`. The alternate (all offsets from its start; identical in the
three siblings modulo the relational fields) then:

1. **Stores the slice verbatim.** `mov [rsp+0x20], rsi` and
   `mov [rsp+0x28], rdx` place `{p, L}` at frame `+0x20/+0x28`, and
   `mov byte [rsp+0x18], 6` writes discriminant byte `6` immediately
   before them, forming a 24-byte tagged value at `rsp+0x18`. No
   instruction in the body dereferences `p` or reads a payload byte.
2. **Builds three descriptor pairs on the stack.** `{rsp+0x7 byte
   address, per-sibling .data.rel.ro address}` at `rsp+0x8`;
   `{rsp+0x18 (the tagged value), qword loaded from .got slot
   0x64dfed0}` at `rsp+0x30` — the slot binds by `R_X86_64_RELATIVE` to
   the 705-byte function at `0x5c4f380` (boundary); and
   `{rsp+0x8, per-sibling 16-byte dispatch shim}` at `rsp+0x40` — each
   shim loads `[rdi]`, `[rdi+0x8]` and jumps to the word at
   `[[rdi+0x8]+0x18]` (bodies byte-identical, hash-pinned).
3. **Calls its helper** (A `0x18be120`, B `0x3046740`, C `0x4892290`;
   154 bytes each) with `rdi` = out `+0x8`, `rsi` = the shared message
   piece at `0x44f07a` — the pinned 28 bytes are a length-prefixed
   fragment whose legible text is `invalid type: ` followed by
   `, expected ` — and `rdx` = the descriptor at `rsp+0x30`. The helper
   is a boundary: pinned facts are its tag test on the third argument
   (`test r14b, 1` — the alternate's descriptor pointer is an even stack
   address, so the first path, a call through `.got` slot `0x64df6e8`
   binding to `0x141e3a0`, is the taken one), its store of byte `6` at
   `[rdi]`, and its copy of three qwords from a stack triple to
   `[rdi+0x8]`, `[rdi+0x10]`, `[rdi+0x18]`. Its internals are not traced.
4. **Writes the error tag and returns.** After the helper call the
   alternate stores qword `2` at `[out]` — the same result tag the
   decoder writes at out `+0x0` for its short-payload error record
   (#2442 stage 4) — sets `rax` = out and returns. The output is an
   error-tagged value whose `+0x8` payload was produced by the helper,
   not a decoded parameter value.

So, to the mission's three-way question: the alternate calls **neither
the same entry nor a different decoder entry, and it does not parse
inline** — it calls exactly one helper, whose business is the tagged
byte-`6` value and the `invalid type` message piece.

**The gated second site.** At decoder `+0x102f` a second route reaches
the alternate: the window advances the reader cursor by the declared
length (`r15` = cursor, `r14` = length, both pinned by the
cursor-advance stores), calls the shared gate function at `0x16815e0`
through `.got` slot `0x64dfca8` with `(rsp+0x70 temp, p, L)`, and only
when the temp's first dword equals `1` calls the alternate with
`(rsp+0x20 temp, p, L)` — after which the decoder tests the temp's first
dword against `2`. The window is byte-identical across the three
decoders modulo the gate-call and alternate-call displacements, both
checked relationally. Which route feeds this window is **not**
established here (Limits).

## Result summary

- `dl` at every censused decoder entry is `0`; the bin supply's entry
  route is the only reachable one as wired, and the `dl != 0` alternate
  route is dead from every static caller.
- If `dl != 0` were delivered, the slice would not be decoded: the
  alternate packages `{p, L}` as a discriminant-`6` byte-string value
  into an error descriptor and the result carries tag `2`.
- The alternate is additionally reachable inside each decoder through
  the gated second site, whose product is the same error-shaped result
  (the decoder post-checks the temp tag against `2`).

## Explicit boundary and next question

What could set `dl` nonzero through a channel the census cannot
enumerate is not established (Limits). The route feeding the gated
second site's length window inside each decoder is not traced, and the
gate function `0x16815e0` is recorded as a slot binding only. What the
helper and its `.got` callees do with the descriptor beyond the pinned
writes — in particular whether the payload bytes are ever read while the
error value is materialized — is not established; within the alternate's
own body the payload is stored, never dereferenced. The discriminant
byte and message piece are recorded as bytes; no Rust type name is
asserted for them or for the descriptor pairs. The parents' own input
provenance (which message fields reach the two call sites) remains as
open as the caller packet left it. No gate is claimed.

Next question: what does the helper's first-path callee (`0x141e3a0`,
via slot `0x64df6e8`) write for the descriptor at `rsp+0x30` — does the
payload length or content reach the materialized error value at
out `+0x8`, and along which route does the gated second site's length
window get its `(cursor, length)` pair?

## Reproduce and validation

From repository root with the materialized pinned capture and native GNU
tools on PATH:

```sh
python3 -B tools/priority_prefix_dl_route_static.py --output research/work-items/RE-003-node115-priority-prefix-dl-route
python3 -B -m unittest discover -s tests -p test_priority_prefix_dl_route_static.py -v
(cd research/work-items/RE-003-node115-priority-prefix-dl-route && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot. During
generation the checker additionally parses each decoder's native export
and asserts every pinned site is a native instruction start and that the
alternate block's only direct branch predecessor is the shared tail's
`dl` branch. Wrong-release, truncated and same-size modified public
inputs are rejected before output creation.

Focused controls alter the alternate's discriminant immediate, its
helper-call displacement and a slice-store opcode, the decoder tail's
`dl` test byte, the gated site's argument move, a parent `xor edx, edx`,
a parent call opcode (E8→E9, breaking the census), a helper body byte
and an FDE record; each makes the checker reject the counterfactual.
Below the full public digest gate, this checks the named obligations,
not arbitrary-byte error detection or target execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and all
progress gates are preserved. No hosted-CI result or whole-component
completion is claimed.
