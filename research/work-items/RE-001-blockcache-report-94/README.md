# RE-001: node #94 BlockCache report formatter 0x514f770

Bounded question: what does node #94 function 0x514f770 render from a
snapshot object, which fields feed each line, and how are the
saturating window, the clock chain and the per-entry ratios computed?

## Answer

0x514f770 renders one `BlockCache` report into the destination string
(rdi; the function returns void). The snapshot object (rsi, kept in
r13) is 0x138 bytes and shares its layout with the timed-snapshot
packet (RE-001-timed-snapshot-94): +0x120/+0x124 counters, +0x128 raw
clock value, +0x130 commit value, +0x20 identity string.

Header line, in order (literals verified byte-for-byte in `.rodata`):

```
Block cache <identity> capacity: <scaled +0x00> usage: <scaled +0x08>
table_size: <+0x10> occupancy: <+0x18> collections: <+0x120>
last_copies: <+0x124> last_secs: <accessor / 1,000,000.0>
secs_since: <(clock - commit) // 1,000,000>
```

then a newline, then `Block cache entry stats(count,size,portion):`,
then one item per nonzero entry, then a final newline:

```
 <name>(<count>,<scaled value>,<ratio>%)
```

- The accessor 0x514df50 returns `max(0, [snapshot+0x130] -
  [snapshot+0x128])`. Its negative arm (`js` to the unsigned-to-double
  conversion) is unreachable for its own range; the model converts the
  unsigned value directly.
- The clock chain is a 3-node sentinel-compared walk (sentinel cell
  0x5777bc8, slot +0x98, wrapper links +0x20): head, one compared node,
  one unconditional node. It is distinct from the timed-snapshot
  4-node walk, though it shares the cell and slot.
- `secs_since` uses the unsigned divide-by-1,000,000 magic
  (0x431bde82d7b634db, shift 18 after the 128-bit multiply), verified
  against integer division by 1,000,000 for edge and random 64-bit
  values -- the same divisor as `last_secs`.
- The scaled-value helper 0x5430570 converts its input as an unsigned
  64-bit value, divides by 1024 repeatedly while the result is >=
  1024.0, stepping KB -> MB -> GB -> TB, and formats `%.2f %s`.
- Each entry ratio is `value * 100.0 / snapshot+0x00` as doubles; a
  zero denominator yields `inf` (`nan` when the value is also zero),
  as in C++ double division.
- Entry names come from the runtime-populated `.bss` table at
  0x578c2e0 (14 records of 0x20 bytes: pointer, length, 16 unused
  bytes). The binary retains no names, so the model takes them as
  parameters and claims nothing about their runtime contents.

Doubles inserted through the ostream (`last_secs`, entry ratios) use
C++ default formatting (6 significant digits); the model uses Python's
`.6g` format, which matches it.

## What is NOT claimed

The identities of the snapshot, clock-holder and wrapper objects; the
clock values' time unit (the labels say secs, but the divisors do not
pin a unit from the bytes alone); the runtime contents of the `.bss`
name table and the sentinel cell; which landing stub serves which call
site; the reaching path (the two direct callers are census only). The
mnemonics `endbr64` and friends are genuine instructions present in
the target binary, not placeholders; instruction-level detail lives
only in the raw disassembly excerpts, kept verbatim and whole-function.

## Files

- `window.objdump.txt` — whole 0x514f770..0x514fd30 function, verbatim.
- `cleanup.objdump.txt` — the exception cleanup block 0x514f71a..0x514f770
  (it sits immediately before the window and has no FDE of its own).
- `accessor.objdump.txt` — whole 0x514df50..0x514df80 (function plus
  int3 padding to the next FDE), verbatim.
- `helper.objdump.txt` — whole 0x5430570..0x5430780 (function plus int3
  padding to the next FDE), verbatim.
- `caller1.objdump.txt`, `caller2.objdump.txt` — call-site samples
  around 0x514ff28 and 0x515747d (samples, not whole functions).
- `records.json` — semantic records only (no per-instruction list).
- `frames.txt` — the three FDE lines (window, accessor, helper).
- `relocations.txt` — PLT stubs used by the window and the helper.
- `verify.py`, `export_excerpts.py` — the packet's own checkers.

Evidence bound to one artifact: `work/hl-node-94.bin`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(provenance/artifacts.json, artifacts/node/94/hl-node).

Environment limits, stated honestly: this VM has no cargo/rustc, no
git-lfs and no Ghidra/Java, so the model is a Python reconstruction
of established semantics, not an execution of the target binary; the
entry names, chain nodes and sentinel value are taken as parameters
because their runtime contents are not retained locally.

Objdump used: the system `objdump` on this VM; run
`verify.py --binary work/hl-node-94.bin` from the repository root to
re-check every excerpt byte-for-byte against the binary.
