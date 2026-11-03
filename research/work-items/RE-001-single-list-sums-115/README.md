# RE-001: node #115 single-list field sums 0x5f13060 / 0x5f13100

## Task and bounded question

Task RE-001. Question: what do the two neighbouring 42-byte windows at
0x5f13060 and 0x5f13100 compute over the intrusive list they share, and
how do their three getters expose that computation end to end?

## Answer in one paragraph

Both windows walk the same intrusive list (header + 0x00 holds the first
node, node + 0x00 the next node, node + 0x10 the payload, walk ends when
a next pointer equals the header; an empty list returns 0) and add one
qword per payload in 64-bit wrapping arithmetic: window A sums payload +
0xa70, window B sums payload + 0xa78. Getter A (0x5eeb510) and getter B
(0x5eeb540) each store their window's sum to an out-pointer and return
1. The composite getter (0x5eeb570) stores a clamped remainder: base =
record + 0xa70 + A(list) + G(inner + 0x30 + 0x40), doubled = 2 * (B(list)
+ record + 0xa78), result = base - doubled when doubled < base
(unsigned, on wrapped values), else 0 — and returns 1. The record is
inner + 0x8e8, where inner = outer + 0x788 and the list is inner +
0x8f8.

## Why this is one complete behavior, not a fragment

The two sums are not submitted alone: the packet pins both windows whole,
both direct getters whole (so each sum is observable on its own), and
the composite getter whole (so the two sums combine with the
distinguished record field into one observable clamped result). The
0x5f6ad70 callee inside the composite is the only part modelled by
contract: it is called exactly once, its single argument is recorded,
and its return value is added into the base. Its internals were not
read and nothing is claimed about them.

## Evidence

All excerpts are verbatim objdump output, whole-function, unmodified.
Regenerate them with `export_excerpts.py` (or by hand):

```
objdump -d --start-address=0x5f13060 --stop-address=0x5f1308a work/hl-node-115.bin
objdump -d --start-address=0x5f13100 --stop-address=0x5f1312a work/hl-node-115.bin
objdump -d --start-address=0x5eeb510 --stop-address=0x5eeb535 work/hl-node-115.bin
objdump -d --start-address=0x5eeb540 --stop-address=0x5eeb565 work/hl-node-115.bin
objdump -d --start-address=0x5eeb570 --stop-address=0x5eeb608 work/hl-node-115.bin
```

Note on mnemonics: `endbr64` and the other mnemonics in the excerpts
are genuine instructions present in the target binary, not
placeholders. Instruction-level detail lives only in these raw excerpt
files; `records.json` carries semantic records, not a per-instruction
mnemonic list.

## Binding

Binary: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
matching `provenance/artifacts.json` entry `artifacts/node/115/hl-node`
(size 105896032) exactly. Frame records are in `frames.txt`
(`readelf --debug-dump=frames` lines for the five windows; CIE 0, no
LSDA, no landing pad). `relocations.txt` records the RELA scan (no
RELATIVE addend equals any window start) and that no window contains a
rip-relative reference, a PLT call, or a stack canary (the composite's
`sub rsp,8` is call alignment only).

## Census

Whole-file scan for direct `e8` calls (address = file offset + 0x1000,
the convention objdump uses for this binary), `e9` tail jumps, qword
hits, and RELATIVE addends; every call site was confirmed as a real
call by disassembling its containing FDE from the FDE start:

- 0x5f13060: 2 direct calls (0x5eeb526 in getter A, 0x5eeb5a8 in the
  composite), 0 tail jumps, 0 qword hits, 0 RELATIVE slots.
- 0x5f13100: 2 direct calls (0x5eeb556 in getter B, 0x5eeb5d7 in the
  composite), 0 tail jumps, 0 qword hits, 0 RELATIVE slots.
- 0x5f6ad70: 1 direct call (0x5eeb5b3 in the composite), the only
  caller found in the whole file.

## Model and tests

`tools/single_list_sums_115.py` implements the two sums, the two
getters, and the composite (with the G callee as a caller-supplied
callable, by contract). `tests/test_single_list_sums_115.py` covers
empty/single/multiple lists, 64-bit wrapping on both sums, both
getters, the composite's positive/zero arms, the G contribution, the G
argument (field30 + 0x40), the literal wrapping comparison, a cyclic
chain (model raises; the binary would loop forever), and packet checks.

## Honesty limits

- The 0x5f6ad70 callee's internals were not read.
- The record type and the meaning of fields + 0xa70 / + 0xa78 beyond
  the arithmetic here are not claimed.
- Which outer objects reach the getters was not traced; only the call
  sites are claimed.
- A cyclic chain never terminates in the binary; the model raises
  instead (a model safety guard, not binary behaviour).
- `make doctor` fails on missing providers (pre-existing, same as
  prior cycles); pytest is not installed, so the test file runs under
  plain python3 via its `__main__` runner.
