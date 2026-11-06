# RE-005 node-115 tag-3 supply

## Question

Open edge 1 of the RE-005 time-context writers packet
(PR #2948), left in the same form by the park_timeout
provenance packet (PR #2938) and the timeout-pair writers
packet (PR #2944): driver_ctor `0x5ce01f0` has a tag-3 arm
that #2948 described as wrapping an already-built context.
Which build / call path supplies it — what constructs the
input it wraps, and can any runtime entry point (node start,
restart, tests) reach it?

## Answer

Settled, with the premise corrected: **the tag-3 arm wraps
nothing. It is the constructor's failure encoding.**

The ctor tail at `0x5ce06a0` writes only `[out] = 3` and
`[out+8] = r15`; it touches no driver field. Only the poll
variant can reach it — variant byte 0 jumps straight to the
shared install sequence (`cmpb $0, cfg+8` at `0x5ce0207`,
`je 0x5ce0332` at `0x5ce020b`) — and the boundary-verified
branch census into the tail is exactly two branches plus
one fall-through, all inside the poll path:

- **R1 — Poll::new fails.** `Poll::new` `0x5ceeae0` returns
  `{INT64_MIN, (errno << 32) | 2}` from all three of its
  error exits (epoll_create1 / eventfd / epoll_ctl) and
  closes its own partial fds. The ctor's `neg` / `jo` pair
  (`0x5ce0229` / `0x5ce022c`) catches word0 == INT64_MIN and
  jumps to the tail with r15 = word1, so the caller sees
  tag 3 with `[out+8] = (errno << 32) | 2`.
- **R2 — signal attach fails.** The attach body
  `0x5ce71f0` lazily initialises a global signal state
  (flag `0x64fee38`, fd `0x64fee24`, object `0x64fee20`,
  via `0x5cdf582`), dups the global fd with
  `fcntl(F_DUPFD_CLOEXEC = 0x406, min 3)` (GOT slot
  `0x64e8a18`), registers the dup on the poll's epoll
  (slot `0x64e12c0`, event flags `0x80002001`, data 1),
  and on success copies the poll pair plus a fresh
  registration Arc and the dup fd into its result. Its
  two failure exits — fcntl at `0x5ce729c`, epoll_ctl at
  `0x5ce72f0` — write the same `{INT64_MIN,
  (errno << 32) | 2}` pair. The ctor's compare at
  `0x5ce02c2`–`0x5ce02d6` diverts that word0 to the
  cleanup (dup fd close, registry Vec element drop,
  buffer free, eventfd close at `0x5ce067b`–`0x5ce069a`),
  which falls through to the tail with the same error
  word in r15.
- **R3 — the post-registration block's `je` at
  `0x5ce0670` is value-unreachable.** The block is
  entered only from the `jne` at `0x5ce02d9` (attach
  success). There rcx is still the `movabs INT64_MIN`
  of `0x5ce02c2`, incremented once at `0x5ce066a` — a
  register-write scan finds no other rcx write in the
  block, and the only other rcx writes in the span sit
  in the install sequence, which this path enters only
  after the compare — while rax is the attach word0
  reloaded through `[rsp+0xc8]`: on success the
  Poll::new capacity (0x400 under the artifact's own
  config constructor), the failure word having been
  diverted. `capacity == INT64_MIN + 1` can never hold,
  so the branch never fires; the block's real exit
  loops back into the install sequence at `0x5ce0382`.

The supply chain above the ctor is closed. The ctor's
only callers are the two call sites of the runtime
builder `0x5cf9600`. The builder has no direct callers
and exactly one pointer reference in the artifact: the
`.rela.dyn` type-8 addend at GOT slot `0x64e1760`, which
is also the builder start's only imm64 occurrence in the
whole file. The slot is called at exactly three sites —
`0x15d7026` and `0x15d70c2` in the wrapper body under FDE
`0x15d6fd0..0x15d8447`, and `0x2ae16f2` under FDE
`0x2ae1690..0x2ae27b2`. Every wrapper builds its config
with cfg_ctor `0x5cf93f0` — whose only callers are those
same three sites — which fixes capacity `0x400` at
`[bcfg+0x60]`, `[bcfg+0] = 0`, the flavour argument at
`[bcfg+0xe4]`, and zeroes the dword at `[bcfg+0xe5]`;
each wrapper then overwrites the u16 at `bcfg+0xe5` with
the constant `0x0101`: **variant byte 1 (poll), tag byte
1 (time enabled)**. The builder assembles the ctor
config from those bytes (cfg+0xa = 1 at site 1, 0 at
site 2; cfg+0xb = `[bcfg+0xe7]`), and the ctor reads
only cfg word0, cfg+8 and cfg+9. So every runtime build
in the artifact drives the poll variant with time
enabled, and R1/R2 are the whole supply of the tag-3
arm.

Finally, the builder converts a ctor tag-3 into its own
error `{[+0] = 2, [+8] = error word}` at both call sites,
and both wrappers compare the builder result's tag
against 2 and divert to their own error paths. A tag-3
outcome therefore surfaces as a runtime-build failure:
no caller ever receives a tag-3 context, nothing is
installed from one, and re-initialisation of a wrapped
context cannot arise.

## Evidence

- `records.json` — artifact pin; the five exported
  bodies and four pinned bodies (FDE extent + sha256);
  the rel32 call censuses; the GOT-slot indirect-call
  census with its rela and imm64 censuses; the
  all-encoding tail census (raw candidates
  `0x5ce022c`, `0x5ce0670`, `0x5ce069e`, the last a
  displacement byte inside the close call, rejected by
  boundary verification); the unique tag-3 store; the
  cfg-read census; the rcx/rdx register-write scans;
  121 instruction byte pins.
- `driver_ctor.objdump.txt`, `signal_attach.objdump.txt`,
  `builder.objdump.txt`, `cfg_ctor.objdump.txt`,
  `poll_new.objdump.txt` — full disassembly of the five
  owned bodies.
- `frames.txt` — the FDE lines for all nine bodies.
- `tools/tag3_supply_static.py` re-derives every record
  from the authenticated artifact; `tests/
  test_tag3_supply_static.py` pins them. Run the tool
  with the artifact materialised at
  `artifacts/node/115/hl-node`.

## Open edges

- The two wrapper bodies' source-level identity (which
  node subsystem's runtime build each is) is not pinned:
  no Location static for either was recovered here. The
  claim is limited to the call graph, the three builder
  call sites and the config bytes they write.
- cfg+0xa (1 at builder site 1, 0 at site 2) and cfg+0xb
  (= `[bcfg+0xe7]`, 0 under the artifact's own config)
  are assembled into the ctor config but never read by
  the ctor; their consumer, if any, is outside this
  question.
- The builder's `[bcfg+0] == 1` arm (r13 = `[bcfg+8]`,
  no `0x5cf5db0` pre-call) is not supplied by the
  artifact's own config constructor, which writes 0 at
  `[bcfg+0]`; a config built outside the artifact is
  outside this packet's claim.
- The producer of the global signal state (what creates
  the fd published at `0x64fee24`) is not traced; only
  the attach body's use of it is pinned.
- Why the compiler emits a counted compare against
  INT64_MIN + 1 in the post-registration block is stated
  at byte level only; R3's value-unreachability does
  not depend on the source-level shape.
