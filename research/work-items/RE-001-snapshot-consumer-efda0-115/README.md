# RE-001: map node #115 stats-snapshot consumer 0x5eefda0

## Task and bounded question

RE-001 (node #115 function map). The refresh routine 0x5eef8a0 (open PR
#3049) publishes a 312-byte stats snapshot and hands the copy to two
consumers; this item pins the first consumer, 0x5eefda0 (FDE
0x5eefda0..0x5ef0360, 1472 bytes), end to end: what text does it build
from the snapshot, how are its numbers derived, and where do the
per-entry names come from? The sibling consumer 0x5ef8360 is explicitly
out of scope here (open lead, see below).

## What the routine does

`render(out, snapshot, chain)` — all three arguments are described in
records.json `routine.arguments`. It builds the text in an
`ostringstream` and assigns it to `*out`:

```
Block cache <name> capacity: <fmt cap> usage: <fmt use> table_size: <n>
  occupancy: <n> collections: <seq> last_copies: <n> last_secs: <ratio>
  secs_since: <n>
Block cache entry stats(count,size,portion): <entry> <entry> ...
```

- `fmt` is the human-size helper 0x61d0ba0: `%.2f KB|MB|GB|TB`, scaling
  by 1/1024 until below 1024.0 (fmt.txt).
- `ratio` is `elapsed(+0x130, +0x128) / 1e6` as a double, where the
  helper 0x5eee580 returns `hi - lo` when `lo < hi`, else `hi`
  (elapsed.txt).
- `secs_since` is `(slot_now - snapshot+0x130) / 1,000,000`, unsigned,
  via the magic multiply `0x431bde82d7b634db` (verified equal to `// 1e6`
  on 200,010 values). `slot_now` comes from the 3-link handler walk:
  the first link whose vtable slot +0x98 differs from the walker
  0x5d4d490 is called, or the third link's slot when the first two both
  match (walker.txt, main.txt).
- The entry loop runs 14 slots (counts at snapshot+0xb0, values at
  +0x40, names from the static table at 0x6503dc0). A zero count prints
  nothing. A printed line is ` <name>(<count>,<fmt(value)>,<portion>%)`
  with `portion = value * 100.0 / capacity`, printed `%g` precision 6.
- The 14 names are `std::string` objects built at load time by the
  static initializer 0x5f007f0 from the literals in records.json
  `name_table` (initializer.txt). The table lives in `.bss`, so its
  contents exist only through that initializer — the packet pins the
  initializer whole, including the second table at 0x6503c00 (same 14
  roles, lowercase-hyphen names), whose consumer is not pinned here.

## Correction to open PR #3049

#3049's records.json says snapshot +0x128 is "the chain head value (the
filler's third argument)". That is wrong. The filler stores its FOURTH
argument (rcx — the first slot +0x98 return V, stored at counter_lo
before the filler call) at +0x128: filler prologue `mov %rcx,%r15`
(0x5eef386) and `mov %r15,0x128(%rbx)` (0x5eef4f2). The third argument
rdx (chain head) is never stored into the snapshot. So +0x128 is the
previous produced value and +0x130 the last produced value, which is
what makes `last_secs` (the interval between the two) and `secs_since`
(time since the last produce) read as seconds. The correction is
recorded in records.json `corrections`. (A second, smaller correction:
#3049's stored qwords for the walker read 0x110978/0x15d568; under the
PT_LOAD mapping — vaddr == file offset in the first LOAD segment — the
`.rela.dyn` addend fields sit at 0x10f978/0x15c568.)

## Evidence

All excerpts are raw `objdump -d` output, whole-function, verbatim
(regenerate with `export_excerpts.py`). Instruction mnemonics such as
`endbr64` are genuine instructions present in the target binary, not
placeholders; the JSON in records.json carries semantic records only,
never a per-instruction mnemonic list. The verify script (verify.py)
checks the artifact digest, the manifest, excerpt regeneration
byte-for-byte, every excerpt instruction line byte-for-byte against the
raw binary, every FDE line, the census, and the model spot check.

- main.txt — consumer 0x5eefda0..0x5ef0360 (353 lines)
- cleanup.txt — exception cleanup fragment 0x5eefd4a..0x5eefd9a
- fmt.txt — human-size formatter 0x61d0ba0..0x61d0d96
- elapsed.txt — interval helper 0x5eee580..0x5eee5a5
- walker.txt — walker identity 0x5d4d490..0x5d4d552, re-shipped
  byte-identical from open PR #3049's packet
- initializer.txt — name-table initializer 0x5f007f0..0x5f00b7e
- initializer_cleanup.txt — its landing-pad/dispose loop 0x5f006ac..0x5f007ec
- string_init.txt — std::string-from-literal helper 0x5effdd0..0x5effea0
- string_fini.txt — table destructor 0x5effea0..0x5effef5
- site-5ef0558.txt / site-5ef7aad.txt — the two direct call sites
- frames.txt — all 13 FDEs (9 pinned routines/fragments + 2 callers +
  2 sibling routines cited in the census note)
- callers.tsv / relocations.txt — committed census (see census.py)
- verify.py / export_excerpts.py / census.py — the checkers

Objdump commands used (from the repository root):

```
objdump -d --start-address=0x5eefda0 --stop-address=0x5ef0360 work/hl-node-115.bin
objdump -d --start-address=0x5eefd4a --stop-address=0x5eefd9a work/hl-node-115.bin
objdump -d --start-address=0x61d0ba0 --stop-address=0x61d0d96 work/hl-node-115.bin
objdump -d --start-address=0x5eee580 --stop-address=0x5eee5a5 work/hl-node-115.bin
objdump -d --start-address=0x5d4d490 --stop-address=0x5d4d552 work/hl-node-115.bin
objdump -d --start-address=0x5f007f0 --stop-address=0x5f00b7e work/hl-node-115.bin
objdump -d --start-address=0x5f006ac --stop-address=0x5f007ec work/hl-node-115.bin
objdump -d --start-address=0x5effdd0 --stop-address=0x5effea0 work/hl-node-115.bin
objdump -d --start-address=0x5effea0 --stop-address=0x5effef5 work/hl-node-115.bin
```

## Model and tests

tools/snapshot_consumer_efda0_115.py reproduces the routine (header,
ratio, walk, entry loop, human-size formatting, unsigned-to-double
fixup, magic /1e6, `%g` doubles). tests/test_snapshot_consumer_efda0_115.py
has 16 tests; the `%.2f` table and the `%g` outputs were cross-checked
against C (gcc) during development, and the magic division against
`// 1_000_000` on 200,010 values. Run directly:
`python3 tests/test_snapshot_consumer_efda0_115.py` (pytest is not
installed on this VM).

## What is NOT claimed

See records.json `not_claimed`: what the slot +0x98 handler and the
slot +0x70/+0x78/+0x80/+0x88 producers compute, the exact throw-site
mapping of the five landing pads, the bodies of the two callers beyond
the pinned windows, the sibling consumer 0x5ef8360 / sibling formatter
0x5eedda0 / helper 0x5eebd00, the role-to-index function
0x5f00570..0x5f006ac, and behaviour on a null chain link or a chain
shorter than the walk needs.

## Open leads (not built here)

- The sibling consumer 0x5ef8360 (4494 bytes, one direct call at
  0x5ef96db from the twin caller 0x5ef9520) and its lowercase-hyphen
  name table at 0x6503c00.
- The sibling formatter 0x5eedda0 (FDE 0x5eedda0..0x5eee30c), which
  also calls the fmt helper (site 0x5eedac6) and is called twice by the
  big dump caller (0x5ef674d, 0x5ef712b).
- The helper 0x5eebd00 (three calls from the big dump caller).
- The role-to-index function 0x5f00570..0x5f006ac (jump-table entries
  for indices 1..12).
