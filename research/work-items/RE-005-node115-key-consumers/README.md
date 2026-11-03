# RE-005 node 115: who consumes the rebuild record's key triple and chain tag

Packet type: static evidence (target-bound). Continues
RE-005-node115-config-fetch (PR #2597), whose open edge 5 asked
who consumes the 0x98-byte rebuild record's +0x78/+0x80/+0x88
"key" triple and +0x90 chain tag downstream.

## Question

The config-fetch packet attributed the record: `lookup_d`'s
rewrite writes the "key" field as length / pointer / length at
record +0x78/+0x80/+0x88 and the "chain" tag byte inside the
qword at +0x90 (Local 0, Sandbox 1, Testnet 2, Mainnet 3). The
shapers `lvl4_a` (0x2ae41e0) and `lvl3_c` (0x2cde430) place the
record at phase +0x10, spread it over the phase struct, and hand
an embedded record at phase +0x220 to a gate body. Starting from
gate body 0x2cb6500, which loads [rbx+0x78]/[rbx+0x80] right
after its config-slot check: who consumes the key triple and
the chain tag downstream — fields read, condition applied,
outcome on each branch, per consumer?

## Answer

**The gate never receives the key triple.** Each shaper builds
the embedded record at phase +0x220 from phase +0xc8..+0xf0 —
which on the traced arm is record +0x8..+0x30 — so embedded
+0x0..+0x28 is record data *before* the key field. The shaper
writes exactly two header bytes itself: the chain tag at
embedded +0x70 (phase +0x290) and dispatch byte 0 at embedded
+0x71 (phase +0x291), pinned at all four call sites. A full
bracket census of both shapers shows **no access at all** at
phase +0x298/+0x2a0/+0x2a8/+0x2b0 — embedded +0x78..+0x98 is
untouched by the shapers, so the record's key allocation is
not passed on.

**The gate manufactures the key pair it checks.** Both gates
are structural clones (22,239 B and 22,372 B; the pinned key
path is byte-identical). Gate entry binds rbx = rdi and
dispatches on byte [rbx+0x71]; the shapers select arm 0. On
that arm the gate copies embedded +0x70 (the chain tag) to
+0x72, then path 1 runs:

- `movzx r15d, byte [rbx+0x72]` — the tag byte;
- `[rbx+0x88] = "hl-node"` pointer (.rodata 0x60f0b2 in
  gate_c; the second copy at 0x605ccd in gate_a), `[rbx+0x90]
  = 7`;
- `[rbx+0x120] = 0`, `dword [rbx+0x121] = (tag << 24) + 1`;
- merge: `[rbx+0x78] = rdx` (the pointer), `[rbx+0x80] = rdi`
  (7), `[rbx+0x98] = &[rbx+0x78]`, outcome bytes at
  +0x11c/+0x11d.

A second arm (dispatch byte ≠ 0, not the shaper-driven one)
reaches the same merge with rdx/rdi loaded from a pre-existing
+0x88/+0x90 pair and the tag byte from +0x124. After the merge
the gate builds its config-check seed, calls the config slot
0x64e0a80 callee (the log-state check of the config-fetch
packet), then loads `rsi = [rbx+0x78]`, `rdx = [rbx+0x80]`,
`edi = r15b` and calls the key slot 0x64e0b38. What follows
tests the tag byte (`test r15b,r15b` at gate_c 0x2cb690d) and
the +0x11c outcome byte (compares at 0x2cb6912) — **never the
lookup call's result**, which does not exist (below). The
gate returns an outcome byte in al through its single ret;
the shapers test only zero vs nonzero: zero drops the
embedded record (0x2ca1b80 / 0x2abde10) and tries another
arm, nonzero continues.

**The lookup callee only logs.** Slot 0x64e0b38 resolves to
body 0x150ad00..0x150b305 (1,541 B, exported in full). It has
exactly four rip-relative call sites binary-wide: the two
gates and both shapers (each shaper also calls it directly
with the constant ("hl-node", 7) and the tag). The callee
saves (tag, pointer, length) to its frame and **never uses
the pointer or length as a memory base** (bracket census
through rsi/rdx is empty). It dispatches on the tag byte
through the relative jump table at 0x465704:

| tag | chain   | target    | reference field in global 0x64f0210 |
|-----|---------|-----------|-------------------------------------|
| 0   | Local   | 0x150b209 | none — plain epilogue, returns at once |
| 1   | Sandbox | 0x150ad51 | +0xd0 {cap, +0xd8 ptr, +0xe0 len}    |
| 2   | Testnet | 0x150ad7c | +0xb8 {cap, +0xc0 ptr, +0xc8 len}    |
| 3   | Mainnet | 0x150adb7 | +0xa0 {cap, +0xa8 ptr, +0xb0 len}    |

Tags 4..7 leave the body (table entries 0x150c679/0x150c697);
the traced callers only ever pass the validated tag 0..3. On
tags 1..3 the callee loads the global pointer from slot
0x64e0b40 (→ 0x64f0210, .data; the field qwords are all zero
in the artifact and the lazy dword at +0x1c0 is 3 — runtime
contents are beyond static evidence), copies the selected
reference string out (alloc slot 0x64df480 + memcpy slot
0x64df508), builds a descriptor pairing the copy with the
caller's key, and calls helper 0x14c2b50..0x14c2c47 (247 B,
exported in full) with the crit-msg global 0x64efeb8. The
helper asks its state callee (slot 0x64dffe0 → 0x154cd10)
whether that global's crit-msg state is applied: if yes, it
emits a log record, frees the descriptor's strings and
returns al = 1; if no, it passes a copy of the descriptor to
equality callee 0x154c4e0 and returns its verdict. A nonzero
verdict only makes the lookup callee emit its own log record
(file string "base/src/crit_msg.rs" at 0x43fea4, line 471)
and, if the emit call returns 1, the message descriptor at
0x465b90 (length 0x47, prefix "crit msg initialization not
applied"). Both string copies are freed on every path. No
caller — gate or shaper — tests anything after the call.

**The chain tag's complete downstream life** is: the shapers'
tag-dword load at phase +0xa0 forming their own direct lookup
call's argument and the phase +0x1e8 byte; the embedded +0x70
byte; the gate's +0x72 copy feeding the lookup call and its
post-call zero test; and the lookup callee's jump-table
index. **The key bytes are compared nowhere in any traced
body** — the single byte-equality is delegated one level
below the lookup callee, to 0x154c4e0, and its verdict can
only produce a log line.

**After placement, the shapers read the triple only to free
it.** Guarded exit arms dealloc the `lookup_d` allocation
(sentinel-checked length, dealloc slot 0x64df4a0) through the
spread pair (length at phase +0xa8, pointer at +0xb0) and
through the record pair (length at +0x88, pointer at +0x90);
both pairs name the same allocation in its two placements.
The phase censuses pin every access at the triple offsets,
the tag qword (+0xa0), the tag byte (+0x1e8) and the
ownership flag (+0x205) in both shapers.

## Method

`tools/key_consumers_static.py` verifies the artifact digest,
all eight owner bodies (the two gates and both shapers are
hash- and pin-pinned; `builder_c`, `lookup_d`, `key_lookup`
and `cmp_helper` are exported in full), the gate and shaper
bracket censuses at the offsets of interest, the embedded-key
absence check over the full shaper censuses, the gate caller
census (direct E8/E9 scan plus the empty relocation-addend
set), the four-site key-slot census, the gate key-path byte
pins (identical bytes in both gates), the shaper embedded-byte
pins, the lookup jump table and arm sentinel-compare pins,
the helper pins, both globals' file contents, and every
string re-read through the section table (.rodata identity,
.text −0x1000, .data.rel.ro −0x2000 deltas resolved per
section). It regenerates records.json, frames.txt and the
four exports canonically; verify mode compares byte-for-byte
and prints `{"matches": true, "packet":
"RE-005-node115-key-consumers"}`.

## Open edges

1. Equality callee 0x154c4e0's internals: which descriptor
   fields it compares, and against which member of the
   crit-msg global 0x64efeb8.
2. The runtime contents of the per-chain reference fields in
   global 0x64f0210 (all zero in the artifact): who populates
   them, and with what values — beyond static evidence.
3. The lookup callee's state constructor behind slot
   0x64e0b48 (body 0x1562670, 5,100 B), called once per
   invocation to build the local descriptor block.
4. The gates' later phases: the merged pair at embedded
   +0x78/+0x80 is loaded once more late in each gate (gate_c
   0x2cbb0ba/0x2cbb0c3; gate_a 0x2aefb11/0x2aefb29), and
   embedded +0x90 is address-taken at gate_c
   0x2cb6b4e/0x2cb715f as a sub-object base — the record's
   post-check processing is the gates' remaining bulk.
5. The "infra" callee behind slot 0x64e0eb0 (0x1534810),
   called by the gate when the +0x123 outcome byte is 2,
   with the 5-byte key at 0x60eb60.

Not claimed: any runtime value of the reference strings, any
behaviour of 0x154c4e0 / 0x1562670 / 0x1534810 beyond the
boundaries above, or the gates' post-check record processing.
