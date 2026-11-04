# RE-001-node115-lu-grant-callers

## Claim status: observation

This packet answers packet #193's (PR #2258) explicitly stated next
question: **which caller path grants explicitly (`esi = 1`), and what
unlock or timeout operation does it belong to** — starting from the 26
caller FDEs in #193's records.json.

The answer, with binary evidence for every site, is: **no static caller
grants explicitly**. All 66 grant-wake GOT sites pass `esi = 0`: 65 call
sites have `xor esi,esi` in the two bytes immediately before the call,
and the single tail-call jmp site has its `xor esi,esi` in the same
block (at `0x4fb53dd`). A full-.text direct-jump-target scan shows no
grant site is a jump target, so no jump can skip a site's `xor` and land
on the call. The explicit-grant input (`esi = 1`) is therefore never
exercised by any static caller; a grant happens only when #193's
deadline-refresh computation sets `bpl = 1` — that is, only when nodes
are present and (the caller's low byte says grant or the deadline was
refreshed).

The `esi = 1` value does exist inside these caller FDEs — 58
`mov esi,0x1` sites were found across 20 of the 26 FDEs — but every one
of them feeds a different callee: 55 feed the shared helper `0x5c87d50`
(GOT `0x64df9f0`), 1 feeds `0x1557260` (GOT `0x64e0ff8`), 1 feeds
`0x155a430` (GOT `0x64e1070`), and 1 feeds `0x1559e80` (GOT
`0x64e1080`). Zero feed the grant slot `0x64e1000`. The caller-side
operation is therefore not "some callers grant, others do not" but
"every caller asks for a deadline-decided grant, and `esi = 1` belongs
to other operations entirely."

The worked example is FDE `0x4fb52e0..0x4fb5435` (341 bytes), one of the
26 callers, decoded end to end. It is a gate-release operation: acquire
the slot gate (`0 -> 8`), do indexed payload work, release the gate
(`8 -> 0`), and — on release failure only — fall back to grant-wake
with `esi = 0`. Both of its grant sites (a normal-path tail-call jmp
and an unwind-path call) pass `esi = 0`, and four more callers show the
same release-failure shape (a `lock cmpxchg [rdi],rcx` `8 -> 0` attempt
whose `jne` lands on a tail block that calls grant-wake with `esi = 0`).

## Scope

Included:

- The full FDE `0x4fb52e0..0x4fb5435`: gate acquire, timed-wait retry
  loop, flag-helper call, 24-byte-stride entry access with a saturating
  decrement and a zero-count completion call, gate release, the
  release-failure grant fallback on both the normal and unwind paths,
  and the index-out-of-bounds panic path.
- The complete 66-site `esi` census: every site's kind (call/jmp),
  containing FDE, `xor` address, and `rdi` writer (same-block, or the
  predecessor block for the four tail sites), with the `rdi` class
  distribution (32 `r14`, 13 `lea` static, 12 `[rsp+0x10]`, 6 `rbx`,
  2 `r15`, 1 `rax`).
- The complete 58-site `mov esi,0x1` census inside the same 26 FDEs,
  with each site's next indirect call and its GOT resolution, proving
  `esi = 1` never reaches the grant slot.
- The panic provenance: `base/src/l1_map/entry.rs:64:17` with the
  message `Out of bounds access`, which names the operation family
  (l1_map entry access) for the worked-example FDE.

Excluded:

- The internals of the direct callees: the flag helper `0x4dccf20`
  (992-byte FDE) and the completion helper `0x4da86a0` (443-byte FDE).
  They are referenced by address only, so the payload's selection rule
  (what the flag means, which entry the index names) is described
  mechanically, not semantically.
- The internals of the `esi = 1` callees, including the shared helper
  `0x5c87d50` (540-byte FDE; its entry tests `esi` and issues a `lock
  cmpxchg`, but it is not decoded here). The census point is only that
  `esi = 1` is routed to other callees, never to grant-wake.
- Any runtime behavior. Analysis is static only; the node binary was
  never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```sh
objdump -d -M intel --start-address=0x4fb52e0 --stop-address=0x4fb5435 \
  artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node   # GOT slot resolutions
python3 tools/node115_lu_grant_callers.py
python3 -m unittest tests.test_node115_lu_grant_callers -v
```

## The worked example: FDE 0x4fb52e0, end to end

Body proper `0x4fb52e0..0x4fb53bb` (219 bytes, 59 instructions, single
`ret` at `0x4fb53ba`); tail `0x4fb53bb..0x4fb5435` (122 bytes, 32
instructions, including the unwind path and the panic path). CIE
`0039672c` (`zPLR`), the same CIE as #192/#193. No `nop` padding.

Entry: `rsi = [rdi]` (call it `P`); `rbx = P + 0x10` (the slot-word
address). The struct's `+0x8` dword is the payload input.

1. **Acquire.** `lock cmpxchg [rsi+0x10],rcx` at `0x4fb52f7` with
   `rcx = 8`, `rax = 0`: try slot `0 -> 8`. On failure (`jne
   0x4fb53bb`), the contention path saves `rdi`/`rsi`, calls the timed
   wait (`0x64e0ff0` -> `0x5bb2440`, #190) with `rdi = slot`,
   `edx = 0x3b9aca00 = 10^9` (the untimed sentinel), and `rsi = P`
   (dead on the untimed path per #190 — the caller does not bother to
   clear it), then restores `rdi`/`rsi` and jumps to the payload at
   `0x4fb5303` without re-acquiring. The wait's return value is
   ignored: the untimed wait returns only on wake, so reaching the
   payload means the gate was yielded by a waker, not re-won by a
   second `cmpxchg`.
2. **Payload.** `rsi = P + 0x18`; `edx = [rdi+0x8]`; direct call to the
   flag helper `0x4dccf20`, which writes a 1/0 flag to `[rsp+0x8]`.
   If the flag is not 1, the payload is skipped (`jne 0x4fb53a3` to
   release). If it is 1, the helper's outputs (`[rsp+0x10]`,
   `[rsp+0x18]`, `[rsp+0x20]`) drive a 24-byte-stride entry access:
   `entry = base + 24*idx + 8`, with an index `>=` capacity (from
   `[rcx+0x18]`) falling to the panic path. `[entry]` is read as the
   count and stored back as a saturating decrement (`count - 1` for
   `count >= 1`, `0` for `count == 0`, via `cmp`/`adc`). If the original
   count was `<= 1` — the count just hit zero, or was already zero —
   the helper outputs are copied to `[rsp+0x38..0x58]` and the
   completion helper `0x4da86a0` is called; if the count was `> 1`,
   the completion call is skipped (`ja 0x4fb53a3`).
3. **Release.** `lock cmpxchg [rbx],rcx` at `0x4fb53aa` with `rcx = 0`,
   `rax = 8`: try slot `8 -> 0`. On success, epilogue and `ret`. On
   failure (`jne 0x4fb53da`), the tail block sets `rdi = rbx`,
   `xor esi,esi`, and tail-calls grant-wake (`jmp 0x4fb53e8` via GOT
   `0x64e1000`). The slot word changed under the holder — waiters
   arrived — so the holder wakes them through grant-wake rather than
   silently dropping the gate.
4. **Unwind path.** At `0x4fb5409` the same `8 -> 0` attempt runs
   (`0x4fb5413`); on success it calls `_Unwind_Resume`, and on failure
   it first calls grant-wake with `esi = 0` (`0x4fb5427`, `xor` at
   `0x4fb5425`) and then resumes. Even on unwind, waiters are woken.
5. **Panic path.** At `0x4fb53ee`, an index-out-of-bounds panic via
   wrapper `0x64df770` with message `Out of bounds access` (20 bytes
   at `0x9171a2`) and Location `base/src/l1_map/entry.rs:64:17`
   (struct at `0x649cc08`; the file string at `0x4402cd` is 24 bytes;
   the `line = 64`, `col = 17` fields are stored inline). The operation
   family is therefore l1_map entry access, consistent with the
   24-byte entry stride in the payload.

## The 66-site esi census

Method: for each of the 66 GOT sites (byte scan for `ff 15`/`ff 25`
with a displacement resolving to `0x64e1000`, cross-checked against
the objdump-boundary census — identical sets), the containing FDE was
resolved from `.eh_frame`, and the block containing the site was
scanned backward for the `esi` writer and the `rdi` writer. For the
four sites that sit in a tail block after a `ret`, the predecessor
`jne` was followed to its block and the writers were read there.
Dominance: a full-`.text` objdump direct-jump-target scan (all `E9`/
`EB`/`0F 8x`/`70-7F` targets) contains no grant site, so no jump can
skip a site's `xor` and land on the call.

Result: 65 call sites, 1 jmp site; 65 `xor esi,esi` immediately before
the call (bytes `31 f6` at `site - 2`); the jmp site's `xor` at
`0x4fb53dd` in the same block; **0 sites with `esi = 1`**.

`rdi` provenance (same-block writer, or predecessor-block writer for
the four tail sites): 32 `mov rdi,r14`, 13 `lea rdi,[rip+X]` (static
slots), 12 `mov rdi,[rsp+0x10]` (8 same-block + 4 tail-predecessor),
6 `mov rdi,rbx`, 2 `mov rdi,r15`, 1 `mov rdi,rax`. Every site's `rdi`
writer is pinned by address and opcode bytes in `records.json`.

The four tail-predecessor sites share one shape, and it is the same
shape as the worked example's release path: `xor ecx,ecx; mov eax,0x8;
mov rdi,[rsp+0x10]; lock cmpxchg [rdi],rcx; jne tail`, where the tail
block is `xor esi,esi; call grant-wake`. These are four more
release-failure fallbacks, all with `esi = 0`:

| site | predecessor `jne` | `rdi` writer | `cmpxchg` |
| --- | --- | --- | --- |
| `0x2a5c641` | `0x2a5c4d6` | `0x2a5c4cc` | `0x2a5c4d1` |
| `0x2a5d539` | `0x2a5d38d` | `0x2a5d383` | `0x2a5d388` |
| `0x4fcb00e` | `0x4fcae5e` | `0x4fcae54` | `0x4fcae59` |
| `0x4fcbbce` | `0x4fcb97b` | `0x4fcb971` | `0x4fcb976` |

Sites per FDE (26 FDEs, matching #193's census exactly): `0x1546aa0`
2, `0x154b3b0` 3, `0x154c700` 2, `0x15516f0` 2, `0x2a5c2e0` 3,
`0x2a5c7e0` 3, `0x2a5cc50` 3, `0x2a5d0f0` 3, `0x2a5d6a0` 3,
`0x4524c20` 2, `0x4524e40` 2, `0x4fac470` 2, `0x4fac710` 2,
`0x4fb52e0` 2, `0x4fca1c0` 3, `0x4fca680` 3, `0x4fcac10` 3,
`0x4fcb120` 3, `0x4fcb590` 3, `0x4fcbe60` 3, `0x4fcc3a0` 3,
`0x4fcc810` 3, `0x4fccd50` 3, `0x5a628d0` 2, `0x5a82670` 2,
`0x5ce7380` 1. Total 66.

## The 58-site mov esi,1 census

Method: every-position byte scan for `be 01 00 00 00` inside the 26
caller FDE ranges, cross-checked against objdump-boundary resolution
of each site's next indirect call — identical 58-site sets. 20 of the
26 FDEs contain `mov esi,0x1` sites (the largest holder is the 28,357-
byte FDE `0x5a82670` with 18); 6 FDEs contain none.

Next-call GOT resolution: 55 to `0x64df9f0` (`0x5c87d50`), 1 to
`0x64e0ff8` (`0x1557260`, from `0x15471c5` in `0x1546aa0`), 1 to
`0x64e1070` (`0x155a430`, from `0x154be06` in `0x154b3b0`), 1 to
`0x64e1080` (`0x1559e80`, from `0x154cc42` in `0x154c700`), and **0 to
the grant slot `0x64e1000`**. The shared helper `0x5c87d50` (540-byte
FDE) tests `esi` at entry (`je 0x5c87e79` when `esi == 0`) and issues a
`lock cmpxchg`, so `esi = 1` selects a real branch there — it is a
meaningful input to that helper, just never an input to grant-wake.

## What this changes about #193

#193's README left open "the caller-side role of each of the 66 GOT
call sites (which unlock or timeout path calls this function, and with
what `esi`)" and reported only three sampled sites, all `esi = 0`. This
packet closes that item completely: every site is `esi = 0`, the
caller-side role is the gate-release fallback (at least for the worked
example and the four tail-predecessor sites, which share the
`8 -> 0`-failure shape), and the `esi = 1` hypothesis is refuted for
all static callers. #193's grant formula stands unchanged — it is now
known that its `bpl = 1` branch is reached only through the
deadline-refresh path, never through an explicit-grant caller.

## Limitations

- The flag helper and completion helper internals are not decoded, so
  the payload's selection rule is mechanical, not semantic (see
  `records.json` limitations).
- The timed-wait call's `rsi = P` is dead only on the untimed path;
  the packet does not claim a second timed-wait signature.
- The jump-target dominance scan is an objdump-level scan, not a
  verifier byte check; the verifier pins every site's bytes, `xor`
  bytes, and `rdi`-writer bytes, and re-derives the 66-site set by
  byte scan.
- No runtime behavior is claimed; the node binary was never executed.

## Next question

The grant-wake caller side is now closed for the static census. The
open thread is the payload side of the worked example: what does the
flag helper `0x4dccf20` select (what makes its out-flag 1), and what
does the completion helper `0x4da86a0` do when an l1_map entry's count
hits zero — is it the entry's removal, a notification, or a recycle?
