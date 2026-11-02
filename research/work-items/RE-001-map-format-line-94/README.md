# RE-001: bind node #94's 21-key map format line 0x514d0c0 with its two value helpers and its 4 callers

Task ID: RE-001. Bounded question: given an object carrying a
21-entry int32-keyed map of doubles, plus a second argument whose
first field is a string, what single formatted line does the
1710-byte function at 0x514d0c0 write, and what does it do to each
key's value on the way there? Answer: it reads every key 1..21
(throwing out_of_range("map::at") on any missing key), converts
keys 1, 2 and 16 to ints, keys 18 and 19 to compact suffixed
strings, and key 3 to a scaled size string, and writes one line
with __snprintf_chk (destination = first argument, limit 2000)
using the format at 0x7e99c0:

    %4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f %9.1f %5.1f %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s %9.1f %9.1f

in the argument order pinned in records.json: first string, key 1,
key 2, key 3's size string, keys 4..15 as floats, key 16, key 17
as a float, key 18's compact string, key 19's compact string, and
keys 20 and 21 as floats. This is a whole complete behavior, not a
fragment: the entry window plus both conversion helpers plus the
throw arms plus the three temporary strings plus all 4 direct
callers end to end.

This window was used before only as the consumer of the
RE-001 map::at bind (foundation-map-at-object-94, PR #1320): that
item claimed the 0x514b490 lookup and cited this function's 14
call sites, but never modelled this function's own body, its
helpers, its inline searches or its snprintf output. Nothing here
redoes that item's ground; the lookup itself is cited, not
re-modelled, and the 7 keys the earlier item did not cover
(1, 2, 8, 11, 12, 15, 17) are bound here through their inline
searches.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Window function: 0x514d0c0..0x514d76e, 1710 bytes, FDE at .eh_frame
  +0x00633df8 (length 0x8c), 2 int3 padding bytes to the next FDE at
  0x514d770. It starts with pushes, not endbr64, and has a stack
  canary (fs:0x28 at rsp+0x108, __stack_chk_fail@plt 0x5660430,
  GOT 0x5778f40). The nopl/nopw bytes inside are alignment padding
  -- all verbatim from the target. Instruction-level detail lives
  only in the raw excerpt files below; records.json carries
  semantic records, not a per-instruction list.
- Map layout (from the map::at bind, re-checked against the inline
  searches): object header at +0x8, root at +0x10; node left +0x10,
  right +0x18, signed int32 key +0x20, double value +0x28.
- PLT: __snprintf_chk@plt 0x56605f0 (GOT 0x5779020),
  __throw_out_of_range@plt 0x5660710 (GOT 0x57790b0, message
  "map::at" at 0x1efeee), _M_dispose@plt 0x5660470
  (GOT 0x5778f60).

## Observations (read from the bytes)

- Reads, in code order: map::at keys 21, 20, 19, 18 (direct calls
  0x514d101, 0x514d118, 0x514d12f, 0x514d151), then an inline
  lower_bound search for key 17, map::at 16, an inline search for
  key 15, map::at 14 and 13, inline searches for keys 12 and 11,
  map::at 10 and 9, an inline search for key 8, map::at 7, 6, 5, 4
  and 3, and inline searches for keys 2 and 1. Together that is
  every key 1..21 exactly once.
- Direct map::at calls throw on a miss exactly as the bound
  0x514b490 function does. Each inline search is a lower_bound
  walk (node key < sought goes right, else the node becomes the
  candidate and the walk goes left); after the walk, a candidate
  equal to the header, or with a key greater than the sought key,
  jumps to a throw arm that checks the canary and calls
  __throw_out_of_range with "map::at" -- so an inline miss throws
  the same way a direct miss does.
- Conversions: keys 1, 2, 16 and the values feeding the helpers are
  truncated toward zero with cvttsd2si. Keys 19 and 18 go through
  helper 0x5430310 (see below) into temporary strings at rsp+0xe0
  and rsp+0xc0. Key 3 goes through helper 0x5430570 into a
  temporary string at rsp+0xa0, after the 2^63 conversion below.
  The three temporaries are disposed in order (key 3, key 18,
  key 19) after the snprintf, and the three landing pads at
  0x514d74e, 0x514d756 and 0x514d762 dispose exactly the
  temporaries created so far on an exception (key 19 only; keys 19
  and 18; all three).
- Key 3's uint conversion: the double is compared against the
  .rodata double at 0x20a7f0 (exactly 2^63). Below it, cvttsd2si
  gives the signed value directly; at or above it, the code
  subtracts 2^63, converts, and flips bit 63 -- i.e. it recovers
  trunc(value) as a uint64, which helper 0x5430570 then reads as
  unsigned (its negative-input path doubles the halved value).
- snprintf: destination = the first argument, limit 2000 (0x7d0),
  flag 2, slen -1, format at 0x7e99c0, 8 xmm registers. The
  first %s argument is the pointer stored at [second argument
  + 0x0] (the code dereferences the saved second argument once
  into r9). The function returns void; its only observable effect
  is the formatted line in the destination buffer.
- Caller census (full binary scans, re-derived, not trusted from
  any index): direct e8 callers of 0x514d0c0 are exactly
  0x5156554, 0x51567d9, 0x5156aae and 0x5156cad, all inside the
  single enclosing function 0x51560b0..0x5157a19 (FDE 0x00634a68).
  No e9 tail jump and no qword vtable reference to it were found.
  The enclosing function's wider semantics are not claimed; only
  the four call sites are bound.

## Helper 0x5430310: compact int string (keys 18, 19)

- Takes (string*, int64). Let a = abs(value) and q = value divided
  with truncation toward zero. By magnitude: a <= 9999 formats
  "%li" with value; a <= 9999999 formats "%liK" with q / 1000;
  a <= 9999999999 formats "%liM" with q / 1000000; otherwise
  "%liG" with q / 1000000000. The divisions are the magic-number
  multiply/shift sequences in the bytes (1000, 10^6, 10^9), with
  the sign correction that makes them truncate toward zero for
  negative values. The result is stored into the string object
  (SSO for length <= 15, _M_create for longer, as in the
  surrounding string code).

## Helper 0x5430570: scaled size string (key 3)

- Takes (string*, int64-as-uint64). The value is read as an
  unsigned 64-bit quantity (negative signed inputs take the
  halve-and-double path). Then: scaled = uint / 1024 (the
  .rodata double at 0x20a600 is exactly 1/1024, compared against
  1024.0 at 0x20aeb8); while scaled >= 1024 and a larger unit
  remains, scaled /= 1024. Units in order: KB, MB, GB, TB.
  Formatted with "%.2f %s". So 0 gives "0.00 KB", 1024 gives
  "1.00 KB", 1048576 gives "1.00 MB", and so on.

## Model and tests

- tools/foundation_map_format_line.py models the key lookup
  (missing key raises KeyError, the model's out_of_range), the
  two helpers, the key-3 uint conversion, and the full format
  line, truncated to 1999 characters as __snprintf_chk with a
  2000 limit would.
- tests/test_foundation_map_format_line.py covers: the compact
  helper at every magnitude boundary including negatives, the
  size helper at every unit boundary, the key-3 conversion
  including the 2^63 arm and a negative double, a full end-to-end
  formatted line, a missing key throwing, packet verification,
  excerpt regeneration, and corruption controls.

## Unknowns (kept separate from observations)

- The source-level type names of the map object, the second
  argument's object, and the 21 values.
- What the formatted line is used for by the four callers.
- The behavior for non-finite doubles (NaN/infinity) through
  cvttsd2si, which the model does not claim.
- The meaning of the map keys beyond their positions in the line.
