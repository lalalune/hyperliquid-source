# RE-001: map node #115 flanking getters 0x5eeb220 / 0x5eeb3a0 / 0x5eeb3c0

Task: RE-001 (#115 function map). Bounded question: what do the three
still-unmapped getters flanking the mapped 0x5eeb250..0x5eeb741 run do,
end to end, including each getter's dispatch (virtual call, stub tail
jump, or refresh call)?

Artifact binding: every result below is bound to node #115, provenance
record `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
materialized locally as `work/hl-node-115.bin` (hash verified exactly
before use). The packet's JSON (`records.json`) holds semantic records
only: window identities, branch site→target pairs, census results, and
by-contract callee notes. Instruction-level detail lives only in the
verbatim whole-function disassembly excerpts in this directory, exported
with the commands below. Mnemonics such as `endbr64` in those excerpts
are genuine instructions present in the target binary, not placeholders:
each excerpt regenerates byte-for-byte from a fresh objdump run (see
`verify.py`), and sampled instructions were checked byte-for-byte
against both a fresh objdump run and the raw binary.

## Windows (all whole functions, .eh_frame FDE CIE 0, no LSDA entry)

- Getter V, 0x5eeb220..0x5eeb241 (33 bytes; FDE .eh_frame offset
  0x356dcc, length 0x18). Args (rdi ignored, rsi = out, rdx = obj):
  vptr = [obj]; *out = movzbl(virtual slot [vptr + 0x478](obj));
  return 1 unconditionally. The rdi argument is never read. Only the
  low byte of the virtual slot's return survives (movzbl), so a slot
  returning 0x1ab stores 0xab and one returning 0x100 stores 0. No
  null check anywhere.
- Getter S, 0x5eeb3a0..0x5eeb3be (30 bytes; FDE offset 0x356eb0,
  length 0x18). Args (rdi = outer, rsi = out): member = [outer +
  0x788]; call stub 0x5d8c9c0(member); *out = the stub's return (full
  64-bit, stored with mov %rax,(%rbx)); return 1 unconditionally. No
  null check anywhere.
- Stub, 0x5d8c9c0..0x5d8c9cd (13 bytes; FDE offset 0x34bbe4,
  length 0x10): loads [member + 0x28] and tail-jumps to 0x5f90da0
  with no ret of its own. Census shows this stub is the sole tail-jump
  caller of 0x5f90da0, and getter S is the stub's sole direct caller,
  so getter S + stub is the sole consumer path into 0x5f90da0.
- Getter R, 0x5eeb3c0..0x5eeb3f3 (51 bytes; FDE offset 0x356ecc,
  length 0x24). Args (rdi ignored, rsi = out, rdx = obj): calls
  0x60d5390(obj + 0x700) and ignores its return; *out =
  sign_extend32([obj + 0x1440]) via movslq; return 1 unconditionally.
  The rdi argument is never read. No null check anywhere.

## By-contract callees (left open, stated explicitly)

- 0x5f90da0: the large hash-set walk reached only through the stub.
  Its internals are NOT modelled here; the packet pins only that
  getter S stores its full 64-bit return for the [member + 0x28]
  sub-object, and that the stub is its sole entry path. A future item
  may map 0x5f90da0 itself.
- 0x60d5390 (refresh): a widely shared utility with over 100 direct
  call sites file-wide (see census.py output); the packet pins only
  that getter R calls it with obj + 0x700 before reading +0x1440 and
  ignores its return. Its internals are NOT modelled here.
- Virtual slot 0x478: class-dependent; the packet pins only the slot
  offset, the argument (obj), and the low-byte masking. The slot body
  varies by class and is NOT modelled here.

## Census (whole-file scan; see census.py)

- Each getter: 0 direct calls, 0 tail jumps, 0 qword hits in .text,
  0 qword hits file-wide, 0 RELATIVE addends — the virtual-getter
  shape, as in the neighbouring mapped getters.
- Stub 0x5d8c9c0: exactly 1 direct call (0x5eeb3af, inside getter S).
- Target 0x5f90da0: exactly 1 tail jump (0x5d8c9c8, inside the stub).
- Refresh 0x60d5390: many direct calls (shared utility); only the
  getter R site (0x5eeb3d7) is claimed for this item.

## Objections / limits, stated openly

- The three getters have no direct callers file-wide; they are reached
  through vtables, like the neighbouring mapped getters. No vtable
  slot is claimed for them here.
- Getter S's observable value depends on the unmodelled 0x5f90da0
  walk; the model takes that computation as a caller-supplied
  by-contract callable and pins only the argument and the full-width
  store.
- Getter V's observable value depends on the class-dependent slot at
  vptr + 0x478; the model pins only the slot offset, the argument,
  and the low-byte masking.

## Reproduce the excerpts

Run from the repository root:

```
objdump -d --start-address=0x5eeb220 --stop-address=0x5eeb241 work/hl-node-115.bin
objdump -d --start-address=0x5eeb3a0 --stop-address=0x5eeb3be work/hl-node-115.bin
objdump -d --start-address=0x5eeb3c0 --stop-address=0x5eeb3f3 work/hl-node-115.bin
objdump -d --start-address=0x5d8c9c0 --stop-address=0x5d8c9cd work/hl-node-115.bin
```

Or run `python3 research/work-items/RE-001-flanking-getters-115/export_excerpts.py`
from anywhere; it regenerates all four excerpts byte-for-byte.

## Model and tests

`tools/flanking_getters_115.py` implements the three getters; the
by-contract callees are caller-supplied callables, never hidden
claims. `tests/test_flanking_getters_115.py` covers low-byte masking,
the stub argument, the refresh call order, signed-field boundaries,
missing-field guards, and packet presence. Run with pytest when
available, or `python3 tests/test_flanking_getters_115.py` directly.
