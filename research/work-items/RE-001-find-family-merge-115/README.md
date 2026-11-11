# RE-001: pin node #115's Find-family merge (hosts A and B, merge driver)

Task ID: RE-001. Artifact: node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How do the two sibling Find-family hosts (host A 0x609d0e0, host B
0x60bedc0) and the merge driver 0x609c8c0 drive the already-pinned
Find pipeline (find_e70 0x6099e70, no_equals 0x609ba30,
kind_dispatch 0x609b700, walker 0x609bcb0, matcher 0x60bb9a0,
worker 0x6097630), and what does each report when the name cannot
be resolved?

## The two hosts

- `host_a` 0x609d0e0 (1662 B): the Find host. out is zeroed
  first. An empty options map calls the descriptor's slot 0x28
  (unless the value's +0x03 byte is 0, which returns the zeroed
  out). Otherwise the value record is copied; a code low byte
  of 0 replaces the copy's name with the literal `"; "` (0x4409b0)
  and runs the worker wrapper 0x6098510 (its Status is discarded,
  only the accumulator survives); then the merge driver 0x609c8c0
  runs and its Status becomes out; the copy's shared control is
  counted-released. When the value's +0x03 byte is set and out is
  ok, the slot-0x28 path runs; when out is an error and the
  accumulator is non-empty, the find_e70 tail runs with a rebuilt
  value (code 0x0101, byte 3 forced to 1) -- and its Status is
  DISCARDED (only the message is freed), so the tail survives
  only through its side effects via the descriptor's slot 0x28 /
  delegate_impl.
- `host_b` 0x60bedc0 (1788 B): the kind-switch Find host. A
  descriptor selector +0xac of 4 returns the zeroed out. The
  options string is copied (range ctor 0x60b7cd0); when the
  value's +0x02 byte is set the copy is unescaped (escape_assign
  0x61d10a0), and a null base then reports Status code 1
  "Could not find option: " + name. A present delegate (+0x18
  != 0) takes the slot-0x20 path with a copied value. Otherwise
  the kind at +0xa8 dispatches (jump table 0x9786b4, 25 entries)
  on the options string into *value_ptr = base + (i32)desc+0x00:
  0x00 bool, 0x01 stoi, 0x02 i32-via-stoll, 0x03 stoll, 0x04 and
  0x06 u32, 0x05 u8, 0x07 stoull, 0x08 stoull alias, 0x09 string
  assign, 0x0a stod, 0x0b-0x10 and 0x18 enum lookups, 0x11-0x16
  the flag/link path, 0x17 hex decode (its return is IGNORED --
  a failed decode still reports success). Kinds 0x11-0x14 and
  > 0x18 report code 3 "Deserializing the option <name> is not
  supported" when the selector is 1..3, else code 4
  "Error parsing:<name>". A parser throw is caught by the
  landing pad 0x60bea8c and reported as code 4
  "Error parsing <name>:<what>".

## The merge driver

`merge_driver` 0x609c8c0 (1902 B): phase 1 clones the source
options map (node_clone 0x6095b80 per node, the source hash
stored into the clone's +0x48, bucket[hash % nbuckets] set to
the slot holding the clone) -- FIRST-WINS on collision: a
later clone whose bucket is already occupied is dropped, not
chained. Phase 2 walks the descriptor's entries in order,
skipping null-table entries, calling the walker 0x609bcb0
(value, desc, entry.table, new-table, entry.field20) per
entry; a walker error or an emptied table ends the walk.
Phase 3 (arg7 present) merges the surviving clones into arg7
(absent keys inserted, rehash 0x5d38260 when needed); phase 4
(arg7 null) reports the first surviving clone as code 1
"Could not find option: " + key when the value code byte is 0
and no walker error was kept, else zeroes out when the value
code byte is set.

## The parsers, hex pair and enum lookups

All nine parsers take a std::string* and ignore its +0x08
length, using strlen -- embedded NULs truncate the input.
`stoull` 0x61d1540 (strtoull, base 10): no digits ->
invalid_argument("stoull"); ERANGE -> out_of_range("stoull");
suffix T/t/G/g/M/m/K/k shifts by 40/30/20/10 (64-bit wrap).
`stoll` 0x61d18a0 is instruction-identical except the
conversion and the literal ("stoll", jump table 0x97ea50).
`stoi` 0x61d1b90 (strtol): the range check
(value + 0x80000000) >> 32 == 0 runs BEFORE the suffix shift;
G/g -> 30, M/m -> 20, K/k -> 10 with 32-bit wrap, and T/t
shifts by NOTHING. `u32` 0x61d1840, `u8` 0x61d17d0 and
`i32` 0x61d1b30 (via stoll) throw out_of_range with the INPUT
text as the message (the exception is built from the input
string in rbx). `stoull_alias` 0x61d1ef0 is two instructions:
endbr64; jmp 0x61d1540. `stod` 0x61d1e30 (strtod): no suffix
handling, trailing content ignored. `bool` 0x61d1480:
"true" -> 1, "false" -> 0, '1' -> 1, '0' -> 0; anything else
throws invalid_argument built from the first argument (the
empty string in host B's kind-0x00 arm).

`hexval` 0x61c7dc0 maps hex digits (else -1);
`hex_decode` 0x61c7fc0 returns False on an odd length or a
bad digit, leaving out PARTIALLY filled on a bad digit.

The seven enum lookups search a map {buckets +0x00, bucket
count +0x08, head +0x10, size +0x18}: linear walk at size <=
20, else the _Hash_bytes walk (seed 0xc70f6907). Six are
byte-identical u8 lookups (0x60be160, 0x60be2b0, 0x60be400,
0x60be550, 0x60be6a0, 0x60be940); 0x60be7f0 is the one u32
lookup. The seven maps (0x6506fe0, 0x6507020, 0x6507060,
0x65070a0, 0x65070e0, 0x6507120, 0x6507160) live in .bss, so
the model takes them as harness-injected EnumMap objects.
Host B binds them: 0x60be160<-0x65070a0, 0x60be2b0<-0x6507060,
0x60be400<-0x6507120, 0x60be550<-0x6507160, 0x60be6a0<-0x65070e0,
0x60be7f0<-0x6507020, 0x60be940<-0x6506fe0.

## Helpers pinned by this item

`worker_wrapper` 0x6098510 (empties the options string, then
calls the worker 0x6097630 with an empty prefix string and
the emptied options string as the accumulator; the worker
itself is re-shipped from #3485), `range_ctor` 0x60b7cd0,
`node_clone` 0x6095b80, `rehash` 0x5d38260. The plain host,
block host, element-scan host, walker and their helpers are
re-shipped byte-identical from #3537.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-find-family-merge-115/verify.py

It checks the binary digest against
`provenance/artifacts.json`, the MANIFEST coverage, the
byte-for-byte regeneration of every excerpt, the raw bytes
of every excerpt line against the binary (plus three seeded
random gate spots, `random.seed(20261106)`), the FDE
presence, the relocation row, the literal read-back, the
census reproduction (3870 rows) and per-target counts, the
model constants (29 new routines), and the model tests
(77 tests in `tests/test_find_family_merge_115.py`).

The model is `tools/find_family_merge_115.py`, self-contained
(it imports nothing from the open #3485 / #3488 / #3537 PRs).

## How the evidence was produced

    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin

per window (see `export_excerpts.py`, which regenerates every
excerpt in `excerpts/`). The census (`census.py`) is one
objdump pass over the whole binary counting direct calls,
jumps and lea references to the packet's routines with the
enclosing FDE per site; it writes `callers.tsv` (3870 rows).
`frames.txt` is the `readelf --debug-dump=frames-interp`
listing filtered to the packet's FDE ranges. The mnemonics
in the excerpts (endbr64 included) are genuine instructions
present in the target binary, not placeholders.

Two rendering quirks the binary shows are modelled
literally: the status builder (0x61cf670) appends ": " +
msg2 when msg2 is non-empty, so a msg1 that already ends
with ": " renders a doubled ": " (e.g. the driver's code-1
report reads "Could not find option: : <key>"); and host
B's code-4 path passes msg1 "Error parsing:" (no trailing
space), so it renders "Error parsing:: <name>".

## Duplicate check

The 29 new routine addresses were checked against the open
PR list (86 open WalkCrypto PRs at cycle start) and by
spaced repo searches: no open PR pins any of them as a
centerpiece. Two routines are referenced as callees in open
PRs -- the stoull parser 0x61d1540 and its alias 0x61d1ef0
appear in #3272 (SkipListFactory ":" setters), #3251 (stats
version-key fetch) and #2560 (delimited-key parse) only as
helper calls, never as the pinned behaviour; re-shipping a
routine as a callee follows the #3485/#3488 precedent, and
the parsers here are arms of host B, not the centerpiece
(the hosts and the merge driver are).

## Open unknowns

- The `"; "` literal host A writes into the copied value's
  name (code low byte 0) is an open unknown: the worker
  parses `;`-separated options, so it likely means "no
  options", but the binary gives no gloss; the model records
  the literal and the branch faithfully.
- Host A's find_e70 tail writes its Status into a local that
  is then discarded (only the message is freed); the call
  survives only through its side effects via the descriptor's
  slot 0x28 / delegate_impl. Modelled literally and pinned
  by test.
- The worker's prefix is the string at element+0x20 (the
  matcher's prefix argument); the element's +0x00 name string
  is the scan's key. The model takes the +0x20 string as the
  prefix.
- The seven enum maps live in .bss (runtime-built); the
  model takes them as harness-injected EnumMap objects, not
  binary reads.
- The global default name at 0x6508980: its runtime contents
  are set by static init and were not located (carried from
  #3440); the model takes "default" as the documented
  assumption.
- The delegate vtable base is not pinned; the model holds
  the delegate's slots as callables supplied by the harness.
- The serializer 0x60ba600 per-kind rules (25 jump-table
  cases) are a boundary; the default model reports every
  kind as serialized.
- Which construction paths install a non-null +0x28
  delegate is not pinned.
- stod is modelled with Python float() on ordinary decimal
  inputs; inf/nan/hex-float edge inputs differ from C strtod.
- The rehash excerpt may end with undecodable padding bytes
  at 0x5d3833a-0x5d3833c; verify.py's raw-bytes check
  confirms the excerpt matches the binary.
