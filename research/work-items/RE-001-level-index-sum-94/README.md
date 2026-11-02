# RE-001: bind node #94's level-index sum formatter 0x514dce0 with its decimal parser, integer formatter and move-assign

Task ID: RE-001. Bounded question: given an outer object, a destination
string and a (pointer, length) view holding a decimal index, what does
the 273-byte function at 0x514dce0 return, when does it leave the
destination untouched, and how is the produced value computed end to
end? Answer: it returns 1 and sets the destination to the decimal sum
of the +0x10 fields of all records, across all levels, whose +0xb7
byte equals the parsed index; it returns 0 with the destination
unchanged when the view is not exactly one decimal index (empty view,
non-digit first character, parser overflow, or trailing characters).
Unlike the level-ratio formatter at 0x514cc10, this caller has no
index-range gate: the parsed index is compared only against record
bytes, so an index matching nothing still returns 1 with "0".

This is a whole complete behavior, not a fragment: the entry window
plus its decimal-parser callee plus the per-level sum loop plus the
integer-formatter callee plus the move-assign callee plus the
temporary-string cleanup end to end.

This window was used before only as a caller census entry in the
string move-assign item (foundation-string-move-assign-94), which
lists the call site 0x514ddab among the move-assign callee's 20
callers but never modelled this function's own body, its parser gates
or its sum rule. Nothing here redoes that item's ground; the
move-assign itself is cited, not re-modelled.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Window function: 0x514dce0..0x514ddf1, 273 bytes, FDE at .eh_frame
  +0x0029ab98 (length 0x30), 15 int3 padding bytes to the next FDE at
  0x514de00. It starts with endbr64, and the parser, formatter and
  move-assign callees also start with endbr64; those are genuine
  instructions present in the target binary, not placeholders. The
  nopl bytes inside are alignment padding, all verbatim from the
  target. Instruction-level detail lives only in the raw excerpt
  files below; records.json carries semantic records, not a
  per-instruction list.
- Stack canary: fs:0x28 saved at rsp+0x48, __stack_chk_fail@plt
  0x5660430 (GOT 0x5778f40) on mismatch.
- Outer layout: [outer+0x788] -> sub-object; [sub-object+0x30] =
  container; the container's level count is the signed int32 at
  +0x50 (sign-extended; count <= 0 skips the loop) and the level
  array pointer is at +0xad8, with 0x18-byte level entries (begin
  +0x0, end +0x8). The +0xad8 array offset agrees with the
  level-report item's container chain.
- String layout (destination at rsi, temporary at rsp+0x20):
  pointer +0x0, length +0x8, union +0x10 (heap capacity / 16-byte
  SSO buffer).

## Observations (read from the bytes)

- Arguments: rdi = outer object, rsi = destination string (saved in
  rbx), rdx = view pointer, rcx = view length. The window builds a
  view struct on the stack: (rsp) = pointer, (rsp+0x8) = length,
  and passes rsp+0x18 as the parser's output slot.
- Decimal parser 0x54307c0 (151 bytes, FDE 0x002badc0, SHA
  1361c480..., matching the level-ratio item's parser exactly):
  rdi = view struct {pointer +0x0, length +0x8}, rsi = output
  slot. An empty view returns 0 and writes 0. Otherwise it scans
  digits, accumulating value = value * 10 + digit in uint64 with
  a checked threshold: value > 0x1999999999999999, or value ==
  0x1999999999999999 with the next digit > 5, returns 0 without
  writing the output slot (that threshold is exactly UINT64_MAX:
  the limit * 10 + 5 = 2^64 - 1). A non-digit stops the scan: the
  function returns 1 with the accumulated value when at least one
  digit was consumed, else 0 with value 0; the view struct is
  left pointing at the stopping character with the remaining
  length, and the struct is updated to the consumed prefix after
  every digit.
- Caller gates, in order, at 0x514dd18..0x514dd2a: parser returns
  0 -> return 0; remaining length at (rsp+0x8) != 0 (trailing
  characters) -> return 0 via the arm at 0x514dde8, which zeroes
  ebp and jumps to the shared cleanup. Only then does it proceed.
  There is no parsed-index range check anywhere in the window.
- Sum loop at 0x514dd30..0x514dd93: container =
  [[outer+0x788]+0x30]; count = movslq [container+0x50]; if count
  <= 0 the loop is skipped and the sum stays 0. Otherwise the
  level array at [container+0xad8] is walked in 0x18-byte steps
  to base + count * 24. For each level, the (begin, end) span of
  8-byte record pointers is walked; for each record pointer p,
  the byte at [p+0xb7] is zero-extended and compared against the
  parsed index, and on equality the int64 at [p+0x10] is added
  to the running sum (starting from 0, wrapping int64 addition).
- Formatter 0x4faf340 (875 bytes, FDE 0x0028c614, SHA
  14d86415..., cited as a callee only): rdi = temporary string
  at rsp+0x20, rsi = sum; it writes the sum's decimal
  representation into the temporary. Its entry thresholds are
  unsigned compares, so this item pins decimal formatting only
  for non-negative sums and leaves the sign treatment of a
  bit-63-set sum as an explicit unknown.
- Move-assign 0x514b4f0 (bound by its own item, cited here):
  rdi = destination, rsi = temporary at rsp+0x20; it moves the
  temporary into the destination. The temporary's heap buffer,
  when present, is then sized-deleted with size capacity + 1
  via _ZdlPvm@plt 0x5660440 (GOT 0x5778f48); the SSO case (the
  temporary's pointer equals its own +0x10 buffer) deletes
  nothing. The shared cleanup at 0x514ddcd checks the canary
  and returns ebp (1 on success, 0 on any failure path).

## Excerpt commands

Run from the repository root:

    objdump -d --start-address=0x514dce0 --stop-address=0x514de00 work/hl-node-94.bin
    objdump -d --start-address=0x54307c0 --stop-address=0x5430860 work/hl-node-94.bin
    objdump -d --start-address=0x4faf340 --stop-address=0x4faf6ad work/hl-node-94.bin
    objdump -d --start-address=0x514b4f0 --stop-address=0x514b5c8 work/hl-node-94.bin

or run `python3 export_excerpts.py` in this directory to regenerate
them. The window excerpt runs to the next FDE start (0x514de00),
so it includes the 15 int3 padding bytes after the window's FDE
end (0x514ddf1); the parser excerpt likewise runs to 0x5430860.
