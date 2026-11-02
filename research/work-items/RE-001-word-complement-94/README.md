# RE-001: budgeted 32-byte complement at node #94 `0x243cd00`

**Bounded question:** What does this previously unbound leaf compute, including
its failure paths? It reads an unsigned budget at `[rdi+0x1e0]`. If the budget
is at most 2, it stores `0x50` at `[rdi+0x1f3]` and returns without charging
it. Otherwise it subtracts 3 and stores the result before checking the unsigned
count at `[rdi+0x128]`. If the count is zero it stores `0x5b` to the status
byte and returns. Otherwise it reads the base pointer at `[rdi+0x120]`, loads
both halves of the final 32-byte element at `base + (count << 5) - 32`,
bitwise complements all its bytes and writes them back. On success it does not
directly write the status byte. Address arithmetic is 64-bit wrapping machine arithmetic;
valid accessible memory and any relevant non-aliasing are caller obligations.

## Binding and evidence

The input is Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
as listed in `provenance/artifacts.json`. The baseline repository revision
is `e5c9b6436876b2a4a39daef813171f9879317699`; no reference source was used.
Addresses are ELF virtual addresses; the `.text` mapping puts this body at
file offset `0x243bd00`.

The FDE describes `0x243cd00..0x243cd64` (exclusive), **100 bytes**, with
section offset `0x7e290`, CIE section offset `0x0`, and FDE record length
`0x10` (excluding its length field). There are **12 padding bytes** `cc`
to the next unwind start `0x243cd70`. The body SHA-256 is
`9b945698d564e97eeb44f5c2789b3b6e1b88440baae44ca96e69b103f2ad4dbc`.
The instruction walk in `walk.txt` gives the raw bytes and all **22 instructions**
in order. Both branch targets land on decoded instruction boundaries. The
whole FDE is accounted for, with returns on all paths. There are **0 callees**
and **0 direct-reference candidates** in the full `.text` byte scan for
`e8` and `e9` rel32 encodings targeting the entry. The scan checks every byte,
including possible immediate/data bytes within `.text`; it is a candidate scan,
not a complete instruction-boundary or indirect-reference census.
A complete `.text` search finds **5 exact body matches**, including this one;
the other byte matches start at `0x3256d50`, `0x3256dc0`, `0x4c903f0` and
`0x4e78d90`. Their function boundaries and ownership are not established here.
The body is therefore not unique, even though this entry passes the novelty
check. A scan of `.rela.dyn` finds **30 relative relocation slots** in
`.data.rel.ro` with this entry as addend, at `0x56a8050` through `0x56b6850`
in steps of `0x800`. These are static pointer relocation records; the records
do not prove that a runtime caller uses them or identify their containing
tables.

Observations: the compare at `0x243cd07` is unsigned; the charge is stored
before the empty-count check. The shift and indexed loads encode a stride of
`0x20`; `pcmpeqd` constructs all-one bits and each `pxor` flips a 16-byte half.
The halves are both loaded before either store. The `movdqu` forms do not
require aligned addresses. Success has no explicit return value assignment:
`rax` contains the shifted count, but no source-level return contract is
inferred. A fault on an inaccessible operand is outside the pure model.

Inference: the fields look like a budget, an element count and a status, and
the mutation resembles a word complement operation. These are descriptive
names for observed offsets; no first-party ownership, opcode identity, type,
unit, allocator or control-flow entry mechanism has been proven. The FDE,
complete local control flow and padding support the extent of this leaf; unwind
metadata alone does not establish arbitrary function boundaries.

## Novelty check

Before committing the packet, the following command produced no matches
(exit status 1) for either hexadecimal or decimal entry address in the
existing research and the supplied PR title lists:

```sh
rg -i -n -e '243cd00' -e '37997824' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees whose behavior requires a separate novelty check. This
check concerns the supplied snapshots only, not later upstream work. The seed
catalogue was inspected as a lead; it does not establish ownership or bounds.

## Reproduction and controls

Run from the repository root with Python 3.10 or later, using only the Python
standard library; no captured binary is executed and no network is used:

```sh
python3 tools/word_complement_94.py --out research/work-items/RE-001-word-complement-94/
python3 -m unittest tests.test_word_complement_94 -v
python3 research/work-items/RE-001-word-complement-94/verify.py
make verify
make catalogue-check
```

The generator authenticates the entire input, parses ELF sections and the
unwind index and FDE, strictly decodes every instruction it relies on, checks
padding and scans the complete `.text` for direct rel32 candidates and exact
body matches, and scans `.rela.dyn` for relative relocation addends. It emits
`records.json` and `walk.txt` deterministically. `verify.py` enforces the
packet file whitelist and manifest, then regenerates and compares both outputs
using the same decoder. Tests cover the authenticated target, budget and count
boundaries, complement vectors, wrong digest, mutated window bytes, altered
branch, injected call, shifted FDE and a synthetic call/jump census. The model
assumes the final element is valid and disjoint from the object and treats
`None` as no status write; it does not execute the target.

## Limits and next step

This is a static semantic binding, not an independently built Rust function or
a byte-equivalence comparison. There is no claim about neighboring functions,
source correspondence, indirect dispatch, other versions, runtime behavior
under memory faults, or whole-node coverage. No component gate is changed.
Next, identify the relocated pointer tables and validate their consumers before
attributing this leaf to a subsystem or using the observed field layout in a
reconstruction.
