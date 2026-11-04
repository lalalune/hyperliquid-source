# RE-006: node 115 forward-1 map readback

Answers the forward-callee packet's next question: the ordered map
that forward 1 (`0x4eeed90`) writes — 24-byte entries
{scrambled hash, key, value = slab slot index} in the buffer at
map + 0x8, bucket words holding entry positions beside the control
bytes at map + 0x18 — is read back by exactly two standalone FDEs.
`contains` (`0x4ef4010`, 319 bytes) is a boolean membership probe
that never loads the entry value; `remove` (`0x4e37a10`, 1,100
bytes) returns the removed entry's value in `rdx`. There is no
standalone `get`: every other read of an entry value is inlined
at the consumer — the four RE-006 insert callers gate on
`contains` and load `entries[position] + 0x10` themselves, and
the consumer at `0x23e4c80` inlines the whole probe. Everywhere
the value is consumed it is used as the 0x110-byte slab slot
index: bound against the slab length at book + 0x90, the slot
state dword required to differ from 2 (vacant). The
node-insert-helper packet already settled that the slab lookups
`0x4da81b0` / `0x4da7880` are not this readback (array-stride
resolvers, no scrambled-hash probe); they are cited, not
re-traced.

## Scope

Measured denominator: the two reader bodies, 319 + 1,100 =
1,419 bytes. Both bodies are retained as complete disassembly
exports. Twelve further FDEs are hash-pinned boundaries only:
forward 1 (the writer, citation), remove's four callers,
the four insert callers, the inlined consumer `0x23e4c80`, and
the two 12,076-byte inlined-probe twins.

## Census (how the readers were identified)

- The scrambled-hash constant `0xf1357aea2e62a9c5` appears 114
  times across 84 FDEs of `.text` (raw byte scan).
- A probe of this layout needs, on top of the hash, a bucket-word
  load (`mov -0x8(base), reg` — the position word sits just
  before the control bytes) and a key compare against
  entry + 0x8 with scale-8 addressing (index × 3 = the 24-byte
  stride). Exactly six FDEs carry the constant and both shapes:
  forward 1 (the writer), `contains`, `remove`, `0x23e4c80`, and
  the twins `0x23d4790` / `0x23d76c0`.
- Near misses, rejected: `0x4ef3170` is an insert for a different
  map (32-byte entries, key at +0x18); `0x4ef8240` / `0x4ef8e20`
  hash a 32-byte key with SipHash-family constants and probe a
  table whose entries sit at +0x0; the remaining constant users
  hash keys for other structures without the entry probe.
- Reference census: `contains` has 81 direct E8 call sites,
  `remove` exactly 4, forward 1 exactly 6 (the four insert
  callers plus the small wrappers at `0x4ed9090` / `0x4edd1e0`);
  zero E9 references and zero `R_X86_64_RELATIVE` addends name
  any of the three. Every E8 site is re-validated as a native
  instruction start inside its containing FDE.

## Trace

1. **contains `0x4ef4010`** — arguments `rdi` = map, `rsi` = key
   by value. It loads the length at map + 0x10 once. Length 0
   returns 0. Length 1 compares the key against the single
   entry's key at entries + 0x8 (`0x4ef4031`) and returns the
   compare as the boolean. Otherwise it recomputes the hash
   (`movabs` `0x4ef4042`, `imul` `0x4ef404c`, `rol 0x14`
   `0x4ef4050`), loads entries (+0x8), control (+0x18) and mask
   (+0x20), walks the bucket chain exactly as forward 1 does
   (bucket word load `0x4ef40bd`, index bound check, ×3 slot
   offset `0x4ef40cd`), and compares the key at
   `entries[index] + 0x8` (`0x4ef40d4`). A match returns
   `eax = 1` (`0x4ef4108`); chain exhaustion returns `eax = 0`
   (`0x4ef4115`). An operand scan of the whole body finds no
   load of the entry value field (+0x10, scale 8) and no store
   to memory at all: **contains never reads the value.**
2. **remove `0x4e37a10`** — arguments `rdi` = map, `rsi` = &key
   (the key is loaded from `[rsi]` at `0x4e37a24`). Length 1:
   the key is compared against the single entry
   (`0x4e37a35`); on a match the length is zeroed
   (`0x4e37a3f`), the entry's *stored* hash is reused to locate
   the bucket word (no hash is computed on this path), and the
   entry value is loaded into `rdx` (`0x4e37a4a`) for return.
   General path: the hash is recomputed (`0x4e37af1` /
   `0x4e37afb` / `0x4e37aff`), the probe mirrors forward 1
   (bucket word load `0x4e37b75`, key compare `0x4e37b90`). On a
   hit: the removed entry's value is loaded into `rdx`
   (`0x4e37c68`), the last entry is swap-copied over the removed
   slot (hash+key `0x4e37c7e`, value `0x4e37c83`, from the last
   entry's value load `0x4e37c74`), the length is stored
   decremented (`0x4e37c88`), the count at map + 0x30 is
   decremented (`0x4e37c4f` / `0x4e37c52`), the control-byte
   marker for the emptied bucket is stored twice
   (`0x4e37c37`, `0x4e37c3b`) with the deleted-marker counter at
   map + 0x28 bumped when the marker becomes 0xff
   (`0x4e37c16` / `0x4e37c27`), the moved entry's bucket word is
   rewritten by a re-probe (`0x4e37dce`), and the function
   returns `eax = 1` (`0x4e37dd3`) with the value in `rdx`. A
   miss returns `eax = 0` (`0x4e37d3c`).
3. **remove's callers** — exactly four, two twin pairs
   (`0x58e1400` / `0x58e1f40`, 2,868 bytes each; `0x58e2a80` /
   `0x58e36c0`, 3,136 bytes each), hash-pinned; caller A is
   traced. It passes `rdi` = the book structure (the map is its
   first field) and `rsi` = a pointer to a local record whose
   first qword is the key. On `eax == 1` it captures `rdx` into
   `rbp` (`0x58e1512`), bounds it against the slab length at
   book + 0x90 (`0x58e1544`), multiplies by the 0x110-byte slab
   stride (`0x58e1558`), and bails unless the slot's state dword
   differs from 2 (`0x58e155f`) before reading the order copy's
   fields and updating the per-side aggregates.
4. **The insert callers' inlined get** — each of the four
   insert callers calls `contains` per walked key (caller 1:
   `0x5904ab0`, `0x5904e86`; caller 2: `0x5908d65`; caller 3:
   `0x590c810`, `0x590cbe6`; caller 4: `0x5910ac5`). On a hit,
   caller 1 (window-pinned; the others are hash-pinned) bounds
   the walked position against the map length and loads
   `entries[position] + 0x10` itself (`0x5904adc`, `0x5904eab`),
   then applies the same slab bound (`0x5904ae4`), stride
   (`0x5904af9`) and state (`0x5904b00`) checks. `contains`
   supplies only the membership gate; the value readback is
   inlined.
5. **The fully inlined consumer `0x23e4c80`** (3,173 bytes,
   window-pinned) — inlines the entire probe: hash
   (`0x23e5503`), bucket word load (`0x23e5581`), key compare
   (`0x23e559c`), a length-1 fast path (`0x23e5444`), then the
   shared consumption block loads the value
   (`0x23e5454`), bounds it against the slab length
   (`0x23e545e`), scales by 0x110 (`0x23e5477`), requires
   state != 2 (`0x23e547e`), and reads the order copy's +0xb0
   fields (`0x23e548b`).
6. **The twin probes** — `0x23d4790` / `0x23d76c0` (12,076 bytes
   each, window-pinned) inline three probes each (key compares
   `0x23d5231` / `0x23d5591` / `0x23d5907` and twins). In the
   pinned windows the hit blocks do not load the probed entry's
   value; the probe is used as a membership test on the key
   itself. Whether the probed table instance is the forward-1
   map instance is **not established** (the fields arrive
   stack-spilled; provenance was not traced).

## Boundary

This proves the read side for standalone FDEs and for the
pinned consumer windows. It does not prove that no other FDE
reads the map through a different hash construction (the census
is scoped to probes that compute this scrambled hash in this
24-byte layout), nor which table instance the twin probes run
against, nor the sorted set's read side. Remove's panic and
cleanup tails are recorded only by their slot bindings
(`0x64df520` → `0x1681da0`, `0x64df620` → `0x1680cbf`,
`0x64df6d0` → `0x141e2da`, `0x64df770` → `0x1680bd0`,
`0x64df848` → `0x1681e40`).

## Next question

Who consumes the sorted set's member keys on the read side —
forward 2's structure from the forward-callee packet (node
handle at set + 0x0, keys as node entries)? The consumer at
`0x23e4c80` already walks forward-2-layout nodes inline (count
word at +0x62, child-index word at +0x60, children at +0x68)
inside the same FDE that inlines the map get; whether a
standalone set-lookup FDE exists, and which key it probes with,
is the open half of the read-side question.
