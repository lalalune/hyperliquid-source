# RE-001: node #94 compaction report entries 0x51599e0

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x51599e0 do end to end — which groups does it walk,
how does it turn each group's key and each entry's key into a
segment key, and what value does it store under that key?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## What the window does

The window (0x51599e0..0x515a7f1, FDE 0x00634c70, 2065 bytes,
15 int3 padding bytes to the next FDE 0x515a800) builds compaction
report entries into a destination map. It returns void; the map
is the result.

- Arguments: outer object in rdi (saved at rsp+0x48), destination
  map struct in rsi (saved at rsp+0x20). The destination map's
  tree member sits at +0x08 of that struct: root at +0x10,
  header at +0x08.
- Collector first: 0x5151970 is called with (outer,
  [[outer+0x788]+0x30]+0x40, the rsp+0x60 struct, the rsp+0x110
  struct). The rsp+0x60 struct carries an empty tree at +0x08
  before the call (header at rsp+0x68: color 0, parent rsp+0x70
  = 0, leftmost rsp+0x78 = header, rightmost rsp+0x80 = header,
  count rsp+0x88 = 0); the collector fills that tree with the
  groups the window then walks. The rsp+0x110 struct is zeroed
  over 0xbc bytes before the call and is never read by this
  window afterwards; its role is recorded as unknown, not
  claimed.
- Outer loop: group nodes from the filled tree's leftmost
  ([rsp+0x78]), advanced with _Rb_tree_incrementP (mutable),
  ending at the header rsp+0x68. A group node carries its int32
  key at +0x20 and an inner-tree header at +0x30 (first node at
  +0x40).
- Group key text: when the group key is -1, the text is "Sum"
  (inline stack string: bytes 0x53 0x75 0x6d, length 3). Otherwise
  the key text is the signed int32 decimal rendering with "L"
  inserted at position 0 by a string replace of length 0 at
  position 0 ("L" at 0x1edb75, 1 byte). The rendering is an
  inlined itoa: the sign is the value's top bit, the magnitude
  is the absolute value (for INT32_MIN the negation wraps and
  the divide loop runs on the zero-extended magnitude 2**31, so
  the text is "-2147483648"), the digit count comes from the
  ladder 9 / 99 / 999 / 9999 / 99999 / 999999 / 9999999 /
  99999999 / 999999999 then 10 digits, the string is built as
  (digits + sign) copies of '-', digit pairs are written from
  the end per divide-by-100 step from the "00".."99" table
  copied onto the stack from 13 .rodata vectors, and the
  remaining one- or two-digit head is written at the buffer
  start plus the sign offset.
- Inner loop: entry nodes from the group header's leftmost
  ([node+0x40]), advanced with _Rb_tree_incrementPK (const),
  ending at the header node+0x30. An entry node carries its int
  key at +0x20 and its double value at +0x28.
- Name lookup: for each entry key, the global int-to-string map
  at 0x578bf20 (map member at +0x08, root at +0x10) is walked
  as a lower_bound (children at +0x10 left / +0x18 right, key at
  +0x20); a missing key throws std::out_of_range with the
  literal "map::at" (0x1efeee), exactly like map::at. The found
  node's name string sits at +0x28 (pointer) / +0x30 (length).
- Segment key: a result string reserves (key length + 11),
  appends "compaction." (0x1ec647, 11 bytes), appends the group
  key text, appends "." (0x1e6d04, 1 byte), is move-assigned,
  then has the name appended and is move-assigned again. The
  segment key is therefore
  "compaction." + group text + "." + name.
- Value: the entry double is rendered by 0x514c050 with the
  format "%f" (0x1df3ed), buffer size 0x148, and the locale /
  global at 0x5778378, into a temporary string.
- Destination store: the destination map is walked as a
  lower_bound over key strings (pointer +0x20, length +0x28):
  memcmp over the common prefix, then the length difference
  clamped to int32 (at or above 2**31 lands on the positive
  side, at or below -2**31 - 1 on the negative side). When the
  candidate key equals the segment key, the "%f" string is
  move-assigned into the node's value string at +0x40 (an
  insert-or-replace store). Otherwise 0x51538a0 inserts a fresh
  0x60-byte node (key string copied at +0x20, empty value string
  at +0x40 with pointer node+0x50 and length 0) via
  _Rb_tree_insert_and_rebalance, and the "%f" string is then
  move-assigned into its +0x40 value string.
- Epilogue: the group key string (rsp+0x90) is disposed when
  heap-allocated, 0x5155710 runs over (outer, destination),
  0x514bee0 tears down the filled tree from its root
  ([rsp+0x70]), the canary is checked, and the window returns.

Callees cited only, not re-claimed: the collector 0x5151970
(0x891 bytes), the insert 0x51538a0 (0x1ce bytes), the teardown
0x514bee0 (0x71 bytes, recursive: right-child recursion, a
0x30-byte item list at +0x38 with 0x514b690 per item, a 0x58-byte
node delete, left-spine iteration), the double formatter
0x514c050 (0x165 bytes), and the epilogue 0x5155710 (0xddd
bytes, five 0x5153a70 find-or-insert sites among its calls).

The sole direct caller is the thin wrapper 0x515a800..0x515a817
(FDE 0x0029b1c0), which forwards (outer, destination) unchanged
and returns 1. Caller census (full .text direct-call scan,
tail-jump scan, whole-file qword scan): exactly that one call
site at 0x515a808; no tail jump, no qword reference. The wrapper
itself has no direct caller, tail jump or qword reference in
the same scans, so its reaching path is left unclaimed.

The exception cleanup at 0x5159968..0x51599e0 (FDE 0x00634cc4)
has staged entries disposing the itoa string, the group key
string and the segment string, then tearing down the filled
tree, ending with the canary check and _Unwind_Resume. The
landing stubs at 0x515a789..0x515a7ec jump into its staged
entries; the LSDA mapping (which stub serves which call site)
is not claimed.

Distinct from the earlier compaction string line 0x514d770
(20-key string lookups, dash rule — a different function) and
from the counters-to-uptime report 0x5159180 (nine fixed
counters plus a db.uptime clock entry — a different window that
shares only the "%f" formatter, the digit-pair table shape and
the map::at pattern).

## Notes on the evidence

Instruction-level detail lives only in the raw disassembly
excerpt text files, kept verbatim and whole-function. The JSON
record holds semantic records only. Mnemonics such as `endbr64`
are genuine instructions present in the target binary, not
placeholders; the checker re-verifies three sampled
instructions byte-for-byte against a fresh objdump run, and
re-verifies every excerpt byte-for-byte.

## Unknowns (recorded, not claimed)

- The identity of the outer object, the groups, the entries and
  the names; the collector's grouping rule; the role of the
  rsp+0x110 struct; the epilogue's follow-up writes; the
  reaching path of the 0x515a800 wrapper; what the stored "%f"
  values mean to a consumer.
