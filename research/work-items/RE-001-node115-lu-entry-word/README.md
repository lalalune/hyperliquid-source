# RE-001: the node #115 lu entry-word lifecycle — claim, lock, waiter-chain push, and FIFO cleanup wake

- Component: `base/src/lu.rs` conversion context, the hash-bucket entry word
  shared by the park queue, the lookup, and the cleanup helper.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #188 (PR #2190, open) left open the entry-word
  lifecycle — what turns the claim value `1` into a pointer-bearing word,
  and what raises it past the small flag states. Answer, in one paragraph:
  the contention helper at `0x5bb6790` does. When a claimant finds the word
  locked or contended past its spin budget, the helper pushes its own stack
  waiter node onto the word with one `lock cmpxchg`, storing
  `(stack node | old low 2 flag bits)`; the word is then a tagged pointer
  to a FIFO waiter chain linked through node `+0x10`, and the cleanup
  helper walks that chain to its oldest waiter, clears the waiter's `+0x18`
  futex word, and wakes it. This packet cites #183 (PR #2106), #184
  (PR #2125), #185 (PR #2137), #186 (PR #2158), #187 (PR #2179), and #188
  (PR #2190, the inviting prior packet) as prior work; their bodies are
  cited, not re-claimed. The new bytes claimed here are the helper body
  only. The lookup, park, and cleanup bodies are #188's claims, referenced
  here by address for the transition sites.

## Correction of #188's threshold phrasing

Packet #188's next question phrased the pointer regime as ">= 5". The code
gates on `>= 4`: the release condition calls cleanup exactly when the old
value is `>= 4` with bit 1 clear, and cleanup early-returns when `[rdi] < 4`.
Installed pointers are 8-aligned stack addresses, so pointer-bearing values
are `>= 8` in practice; 4..7 occur only as transient flag combinations, never
as installed values. The ">= 5" wording is the pointer-bearing regime
described loosely, not a threshold the code tests.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| contention helper (characterized) | `0x5bb6790..0x5bb68d9` | 329 | 104 |
| lookup (cited, #188) | `0x5bb4d00..0x5bb4f78` | 632 | — |
| park (cited, #188) | `0x5bb42e0..0x5bb4663` | 899 | 257 |
| cleanup (cited, #188) | `0x5bb66b0..0x5bb678b` | 219 | — |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000. The helper FDE's CIE is
`0x00000000`; it has one `ret`, at `0x5bb68d8`, followed by `int3` padding.
The helper body SHA-256 is
`a94378e14e8639339101729a199bd051e7795fc54c0ca9f2ff528bffcf902be8`.

## The word state machine

The word is the first qword of a 64-byte hash-bucket entry (entry stride 64,
table pointer variable at `0x64fff28` via GOT `0x64ec148`). Its values:

| Value | Meaning |
| --- | --- |
| `0` | free; the lookup claims it with `lock cmpxchg 0 -> 1` |
| `1` | freshly claimed, no waiters; released by `lock xadd -1` back to `0` |
| bit 0 set | lock held (set by the helper's acquire `cmpxchg`, cleared by a release `xadd -1`) |
| bit 1 set | cleanup in progress (set by cleanup's `cmpxchg old\|2`, cleared on exit) |
| pointer \| flags | waiter-chain head: the newest waiter node address OR'd with the old low 2 flag bits; installed only by the helper's push |

The release rule, identical in the lookup (one site) and the park body
(three release paths — six lock xadd instructions in total, one per queue
per path, matching #188's six-site count), is `lock xadd -1` followed by: call cleanup if and only if
`(old & 2) >> 1 | (old < 4)` is zero — that is, old `>= 4` with bit 1 clear.
Cleanup itself early-returns when `[rdi] < 4` or bit 1 is set, then
`lock cmpxchg`-sets bit 1 and proceeds. Small flag-only values (0..3) never
reach cleanup's pointer path; that path runs only on pointer-bearing words.

## The helper, in order

`helper(rdi = word pointer)` (GOT `0x64ec160`), 329 bytes:

1. **Acquire.** Loop: if bit 0 of the word is clear, `lock cmpxchg [rbx],
   rax|1` at `0x5bb67cb`; on success the helper returns with the lock held.
   This return contract is why the lookup's post-helper path can release with
   a plain `xadd -1` when it finds the table changed: the helper hands back
   a held lock, and the decrement clears bit 0.
2. **Spin.** While the word is `< 4` and fewer than 10 rounds have passed,
   spin with a `pause` backoff of `2^(round+1)` pauses per round, calling
   `sched_yield` (GOT `0x64e1558` → `sched_yield@GLIBC_2.2.5`) from round 3
   on (call at `0x5bb6887`). If the word is already `>= 4`, or 10 rounds
   elapse, the futex path is taken immediately.
3. **Push.** The helper builds a waiter node on its own stack and installs
   it with one `lock cmpxchg` at `0x5bb687a`: the new word is
   `(stack node rsp+0x8 | old low 2 bits)` (`and ecx,3` at `0x5bb6874`,
   `or rcx,r15` at `0x5bb6877`). **This is the transition that turns the
   claim value `1` into a pointer-bearing word**: after ten spins on a
   claimed word, or at once on a pointer-bearing word, the word becomes a
   stack address, hence `>= 8` and past every small-state gate.
4. **Wait.** The helper then futex-waits on the waiter's word:
   `syscall(202, rsp+0x20, 0x80, 1)` — `FUTEX_WAIT_PRIVATE` — at
   `0x5bb68a0..0x5bb68b7` (GOT `0x64e06b8` → `syscall@GLIBC_2.2.5`), looping
   while `[rsp+0x20]` is nonzero. When the word is cleared, it re-reads the
   entry word, resets the round counter, and retries the acquire loop.

## The waiter node (pushed-pointer-relative coordinates)

The pushed pointer is `rsp+0x8`. Relative to that pointer, the waiter node is:

| Offset | Content |
| --- | --- |
| `+0x0` | self address when pushed onto an empty chain, else `0` (stale: recomputed by cleanup's walk; see below) |
| `+0x8` | `0` at push; filled by cleanup's walk with the next-newer node (back-link) |
| `+0x10` | previous head pointer `P` (the word's old pointer bits), or `0` |
| `+0x18` | futex word, `1` while waiting; cleared by the waker before the wake |

The stack slot at `[rsp]` (one qword below the pushed pointer) is set to `1`
but is not part of the node under these coordinates; its role is not
attributed here. The chain links through `+0x10` toward older waiters, so the
word always points at the newest waiter and the oldest waiter is found by
walking `+0x10` links.

## The cleanup drain (worked FIFO trace)

Cleanup (`0x5bb66b0`, cited from #188) is the waiter waker. Given a chain
word → N2 (newest, `+0x10` = N1) → N1 (oldest, `+0x0` = self):

- First release → cleanup: bit 1 is set, the walk follows `+0x10` from N2
  to N1 (fixing N1's `+0x8` back-link to N2 on the way), N2's `+0x0` is set
  to itself (marking N2 as the new oldest), bit 1 is cleared, and N1's
  `+0x18` futex word is cleared and futex-woken (`FUTEX_WAKE_PRIVATE`,
  matching the helper's `0x80` wait). The word still points at N2, now
  self-marked.
- Second release → cleanup: N2's `+0x0` is self (nonzero), so no walk is
  needed; its `+0x8` is `0`, so the word is restored to just the flag bits
  (`old & 1` = `0`), and N2's `+0x18` word is cleared and woken. The word
  returns to `0`; the chain has drained in FIFO order (oldest first).

In general, head `+0x0` caches the oldest waiter (self when the head is
oldest, `0` when stale — the walk recomputes it), so each cleanup wakes
exactly one waiter, the oldest, and the word returns to `0` exactly when
the last waiter is woken. If cleanup finds bit 0 still set on entry, it
restores the word with bit 1 cleared and returns without waking: the lock
holder, not cleanup, owns the next step.

## Call-site census: who uses this protocol

Direct `E8` callers of the lookup (`0x5bb4d00`): exactly 2 — the park body
(site `0x5bb42f1`) and a sibling function, FDE `0x5bb3e50..0x5bb42d9`
(1161B, site `0x5bb3e61`). GOT-indirect callers of the park function:
exactly the 3 sites from #188 (`0x5cf4e8e`, `0x5cf521b`, `0x5cfd965`).
GOT-indirect callers of the helper: 13 sites — 2 in the lookup
(`0x5bb4e67`, `0x5bb4ed2`) and 11 in 7 family FDEs in the `0x5bb1xxx`–
`0x5bb6xxx` cluster (`0x5bb1a60`, `0x5bb2110`, `0x5bb2440` ×3,
`0x5bb4670` ×2, `0x5bb5650`, `0x5bb59d0` ×2, `0x5bb6070`), which share
the table variable (12 `tblvar` loads), the cleanup helper (44 GOT call
sites), and the table-creation helper (9 GOT call sites). The protocol is
one shared mechanism across that family, not a park-only idiom — but the
family functions' individual roles are not decoded here; only their
helper/cleanup call sites are counted.

## The wake-site rdx question: still open, with stronger evidence

Packet #188's second next question — the wake-site `rdx` setup that would
complete a slot-`+0x8` attribution — does **not** close here, and the
evidence against a static close is now stronger:

- The consuming wake body (`0x5cfd8c0`, #187's claim) never writes `rdx`
  before its park call at `0x5cfd965`; `rdx` flows from wake entry.
- The wake-by-ref twin (`0x5cfd600`, 160B) does not call park at all — it
  only runs the guard-byte wait logic — so no sibling establishes `rdx`.
- The wake's two wait helpers are generic PLT imports, not queue code:
  GOT `0x64e01f8` has 390 call sites and GOT `0x64e0f38` has 611 across the
  binary, so no wait-helper return can be attributed as the destination
  queue source.
- The wake has no direct `E8` callers (byte scan over all of `.text`); it
  is invoked only through the Q table's slot `+0x8`. The destination queue
  therefore comes from the vtable dispatch caller, which cannot be
  attributed from this table alone. A static close would need the dispatch
  site, not another reading of the wake body.

## What this does not claim

- The Rust type/trait names of the entry, the word, the waiter node, and
  the queue are not asserted; "entry word", "waiter chain", and "cleanup"
  are behavior descriptions from the atomic operations, not symbols.
- The `[rsp] = 1` stack slot below the pushed waiter node is observed but
  unattributed.
- The family functions' individual roles (beyond their helper/cleanup call
  sites) are not decoded; the table-creation helper (`0x5bb6400`) and the
  table-resize path are context only.
- No gate is requested by this packet; the next question is either decoding
  one family function end to end (the 4525-byte FDE `0x5bb2440`, with three
  helper call sites, is the largest candidate) to see the word-chain pop
  path from the inserter side, or finding the vtable dispatch site that
  would settle the wake-site `rdx` question above.

## Verification

`tools/node115_lu_entry_word.py` passes (target digest, helper body hash,
all transition sites, census 2 / 3 / 13 / 44);
`tests/test_node115_lu_entry_word.py` passes (7 tests, including corruption
controls); `make doctor` reports `analysis_ready` true; `make verify` and
`make catalogue-check` pass.
