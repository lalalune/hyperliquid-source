# Foundation three-field tail gate — node #94 window 0x473b120

## Question

Can one small, previously unclaimed window in node #94 be bound to a precise
rule from its own bytes alone, without a reference label, a matching string,
or a family census?

## Target

- Release: node #94 (Linux x86-64 baseline).
- Captured binary: `artifacts/node/94/hl-node`, 91,774,280 bytes.
- SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Window: FDE `[0x473b120, 0x473b143)`, 35 bytes, body SHA-256
  `8f8e76d62953ecf22b168206dcdb045c4890b8da9fd7b08ee93a7e363c295276`.
- Coordinate system: ELF virtual addresses, no runtime rebase.
- Static analysis only. The captured binary was never executed; no network,
  chain action, or signing was involved.

## Scope

Included: this window alone, its FDE record, its stride padding, its tail
callee's FDE existence (named, not decoded), its one direct caller, and the
relocation scan for a naming record.

Excluded: the tail callee's body (named, not decoded, per the packet #31
precedent), the caller's purpose beyond the call setup it shows, any census
of similar windows, any stdlib type or source-level function, and any
progress gate. No progress files are touched and no gate is claimed.

## Reproduce

```sh
python3 tools/foundation_three_field_tail_gate.py \
  --check research/work-items/foundation-three-field-tail-gate-94/evidence.json
python3 -m unittest tests.test_foundation_three_field_tail_gate
make verify test catalogue-check
```

GNU `objdump` was used for the retained disassembly and frames
(`--dwarf=frames` for the FDE extents). The reference tree was a search lead
only; no inferred implementation was copied, and every claim below is
grounded in target bytes.

## Observations

- FDE record at `.eh_frame` section offset `0x217a50`, CIE at offset `0x0`
  (`zR`, pcrel sdata4), range 35 bytes. The 35-byte body ends at `0x473b143`;
  13 `int3` padding bytes run to the 48-byte stride ending at `0x473b150`,
  where the next FDE starts (`[0x473b150, 0x473b1fa)`, section offset
  `0x5a5860`, CIE at `0x2dc714`). Stride is not the FDE extent; the checker
  locks body and padding separately.
- The window has no `endbr64`: it opens directly with the first compare.
  This is an observation about the retained bytes, not a deviation from any
  prior claim.
- Decoded instructions, in order, all verified from bytes:
  - `cmpb $0x3, 0x88(%rdi)`; `jne +0x19` → `0x473b142` (the ret).
  - `cmpb $0x3, 0x80(%rdi)`; `jne +0x10` → `0x473b142`.
  - `cmpw $0x3, 0x60(%rdi)`; `jne +0x09` → `0x473b142`.
  - `add $0x68, %rdi`; `jmp 0x47301d0` (rel32 `-0xaf72` from `0x473b142`).
  - `ret` at `0x473b142`.
- Rule: return (fall through to ret, rdi unchanged) unless the byte at
  `+0x88`, the byte at `+0x80`, and the word at `+0x60` are all exactly 3;
  when all three pass, rdi advances by `0x68` and control leaves by the
  tail jump. The third test is a 16-bit word compare, so a value such as
  `0x103` fails it even though its low byte is 3.
- No return value is set by this window on either path: the ret path sets
  nothing, and the tail path leaves by jump. The window reads only rdi's
  three fields; no other argument is read, and there are no calls inside
  the window.
- Tail callee, named not decoded: `0x47301d0` has its own FDE
  `[0x47301d0, 0x4730299)` (section offset `0x5a322c`, CIE at `0x2dc714`)
  and starts with a real prologue. Its purpose is unknown and not claimed.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly one direct `e8` site — `0x47b6f24` (bytes `e8 f7 41 f8 ff`),
  confirmed as an instruction start by linear disassembly from its caller
  FDE start (`0x47b4950..0x47b6f8f`, section offset `0x5b0264`). This is
  explicitly not a complete xref census. The caller sets rdi from r13
  (`mov %r13, %rdi`) immediately before the call; caller purpose beyond
  that is not claimed.
- Data edge: a full-section scan of every `.rela.*` section finds no
  relocation record of any type naming this window as addend.
- No scout correction was needed: every scouted element verified exactly
  (FDE range, 35-byte body, all three field tests, the tail jump target,
  the one caller, no naming relocation).

## Inferences

- The "three-field tail gate" label is an inference from the observed rule
  (three field tests gating a tail jump), kept separate from the rule itself.
- The window's position, `0x473b120`, sits far from every previously
  claimed window (nearest claimed: the multiply/xor mixer `0x4b27620`,
  `0x3ec500` away), so no overlap is claimed or implied.

## Unknowns

- The meaning of the three fields, the value 3, the `0x68` advance, and the
  tail callee's purpose are all unknown and not claimed.
- Whether any indirect or non-`e8` caller exists is unknown; the scan above
  is a byte pattern, not a census.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is
  claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a
  naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
