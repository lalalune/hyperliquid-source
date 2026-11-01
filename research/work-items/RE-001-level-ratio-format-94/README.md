# RE-001: bind node #94 level-ratio formatter 0x514cc10 with its decimal parser, per-level ratio, %f formatter and move-assign

Task ID: RE-001. Bounded question: given an outer object, a destination
string and a (pointer, length) view holding a decimal level index, what
does the 233-byte function at 0x514cc10 return, when does it leave the
destination untouched, and how is the formatted value produced end to
end? Answer: it formats the indexed level's ratio with "%f" into the
destination and returns 1, or returns 0 with the destination unchanged
when the view is not exactly one in-range decimal index. The ratio
itself is an unsigned division of two sums over the level's records,
with -1.0 for an empty level or a zero denominator -- and that -1.0 is
not checked by this caller, so it formats as "-1.000000" and still
returns 1.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Window function: 0x514cc10..0x514ccf9, 233 bytes, FDE at .eh_frame
  +0x0029aa40 (length 0x38), 7 int3 padding bytes to the next FDE at
  0x514cd00.
- This function starts with endbr64, and the parser and ratio callees
  also start with endbr64; those are genuine instructions present in
  the target binary, not placeholders. The nopl bytes inside the
  functions are alignment padding, all verbatim from the target.
  Instruction-level detail lives only in the raw excerpt files below;
  records.json carries semantic records, not a per-instruction list.
- Stack canary: fs:0x28 saved at rsp+0x48, __stack_chk_fail@plt
  0x5660430 (GOT 0x5778f40) on mismatch.
- Outer layout, consistent with the RE-001 level-report item: level
  count at outer+0x778 (signed 64-bit, compared unsigned), and
  [outer+0x788] -> sub-object with [sub-object+0x30] = the level
  container; the level array is at [container+0xad8], which is exactly
  how the ratio callee reads it ([(container+0x40)+0xa98]).
- String layout (window temp at rsp+0x20, destination at rsi): pointer
  +0x0, length +0x8, union +0x10 (heap capacity / 16-byte SSO buffer).

## Observations (read from the bytes)

- Arguments: rdi = outer object, rsi = destination string (saved in
  r12), rdx = view pointer, rcx = view length. The window builds a
  view struct on the stack: (rsp) = pointer, (rsp+0x8) = length, and
  passes rsp+0x18 as the parser's output slot.
- Decimal parser 0x54307c0 (151 bytes, FDE 0x002badc0, SHA
  1361c480...): rdi = view struct {pointer +0x0, length +0x8}, rsi =
  output slot. An empty view returns 0 and writes 0. Otherwise it
  scans digits, accumulating value = value * 10 + digit in uint64
  with a checked threshold: value > 0x1999999999999999, or value ==
  0x1999999999999999 with the next digit > 5, returns 0 without
  writing the output slot (that threshold is exactly UINT64_MAX: the
  limit * 10 + 5 = 2^64 - 1). A non-digit stops the scan: the function
  returns 1 with the accumulated value when at least one digit was
  consumed, else 0 with value 0; the view struct is left pointing at
  the stopping character with the remaining length, and the struct is
  updated to the consumed prefix after every digit.
- Caller gates, in order, at 0x514cc59..0x514cc74: parser returns 0
  -> return 0; remaining length at (rsp+0x8) != 0 (trailing
  characters) -> return 0; parsed value >= level count (unsigned
  jae) -> return 0. Only then does it proceed.
- Per-level ratio 0x51ca8a0 (201 bytes, FDE 0x002a1048, SHA
  6cb49a40...): rdi = container+0x40, esi = index (the callee
  sign-extends the low 32 bits). It loads the level array at
  [rdi+0xa98], takes the entry at index * 24 bytes (begin +0x0, end
  +0x8), and walks the record pointers in [begin, end): per record it
  adds [record+0x10] to the denominator and ([record+0x90] +
  [record+0x98]) to the numerator, both as wrapping int64 sums. An
  empty entry (begin == end) jumps straight to the -1.0 return; so
  does a zero wrapped denominator. Otherwise the result is
  (double)(uint64)numerator / (double)(uint64)denominator, using the
  binary's unsigned-conversion sequences (halve-and-double) for
  negative int64 sums. The -1.0 constant is the double at 0x20a278.
- Formatting: the ratio double in xmm0 is formatted by 0x514c050
  with "%f" (bytes at 0x1df3ed) into the temporary string at rsp+0x20
  (edx 0x148, rcx = format address, al = 1; the incoming rsi from GOT
  0x5778378 is passed through as recorded by the formatter's own
  bind). The temporary is then move-assigned into the destination by
  0x514b4f0. The temporary's heap buffer, when its pointer differs
  from its own +0x30 (the SSO case), is sized-deleted with size
  capacity + 1 via _ZdlPvm@plt 0x5660440 (GOT 0x5778f48); the SSO case
  deletes nothing.
- Return value: ebx holds the parser result (1) on the success path
  and is forced to 0 on every failure arm; the function returns ebx.
- Callee census: the ratio callee has exactly one direct-e8 caller in
  the whole .text -- this function, at 0x514cc7f. The parser callee
  has 10 direct-e8 sites (0x514b3d4, 0x514cc4e, 0x514dd13, 0x514ebcf,
  0x5154289, 0x529ec1f, 0x529ecd0, 0x529ee36, 0x529eea8, 0x529f127),
  listed as census only; only this function's site is modelled.
- Window reaching path: a full .text direct-e8 scan, a full .text e9
  tail-jump scan and a whole-file qword-pointer scan found NO caller,
  tail jump or vtable reference to 0x514cc10. The behavior is
  complete end to end through its callees, and only the reaching path
  is unclaimed -- the same situation as the RE-001 level-report item
  (0x514c580), which likewise has no direct caller. This function is
  cited only as a call site (at 0x514ccaa) in the string move-assign
  packet; that packet claims the move-assign function, not this one,
  so this item does not redo its ground.

## Inferences

- The "%f" formatting plus the move-assign means the destination ends
  up holding a human-readable decimal rendering of the level ratio
  (six fractional digits), e.g. "12.000000" or "-1.000000".
- The level-array layout (24-byte entries, record fields +0x10 /
  +0x90 / +0x98) matches the level-report item's container chain,
  so this function is a sibling consumer of the same level-stats
  structure, reached with a level index supplied as text.
- The parser's shape (view struct, checked uint64 accumulation,
  bool return with a trailing-character remainder) is a from_chars
  style decimal parser; the source-level name is not claimed.

## Unknowns

- The source-level name of the ratio: which two quantities the
  summed fields represent beyond their offsets.
- Whether any other consumer distinguishes the ratio's -1.0 sentinel;
  this caller does not.
- The index truncation edge: the caller gates on the full 64-bit
  parsed value, but the ratio callee truncates it to signed 32 bits.
  Level counts above INT32_MAX are outside the modelled range.
- The source-level type names of the outer object, the level
  container and the records.

## Packet contents

- window.objdump.txt: 0x514cc10..0x514cd00, whole window verbatim
  including int3 padding.
- parser.objdump.txt: 0x54307c0..0x5430860, whole parser verbatim
  including int3 padding.
- ratio.objdump.txt: 0x51ca8a0..0x51ca970, whole ratio verbatim
  including int3 padding.
- plt.objdump.txt: both PLT stubs verbatim (0x5660430..0x5660450).
- frames.txt: all five FDE lines (window, parser, ratio, formatter,
  move-assign).
- relocations.txt: the two PLT GOT entries.
- records.json: semantic records only (no per-instruction list).
- verify.py: re-derives the digest, function SHAs, excerpt
  regeneration, FDE lines, relocations and recorded constants from
  the binary; prints ALL CHECKS PASSED.
- export_excerpts.py: regenerates the excerpts with objdump.

## Commands

    objdump -d --start-address=0x514cc10 --stop-address=0x514cd00 work/hl-node-94.bin
    objdump -d --start-address=0x54307c0 --stop-address=0x5430860 work/hl-node-94.bin
    objdump -d --start-address=0x51ca8a0 --stop-address=0x51ca970 work/hl-node-94.bin
    objdump -d --start-address=0x5660430 --stop-address=0x5660450 work/hl-node-94.bin
    python3 research/work-items/RE-001-level-ratio-format-94/verify.py
    python3 -m unittest tests.test_foundation_level_ratio_format -v
