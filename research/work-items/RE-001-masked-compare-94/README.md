# RE-001: masked byte-string comparison at 0x1407ec0

Task/component: RE-001 / foundation. Static function bind, not a
source implementation or a completion gate. Bounded question: Does this leaf find an exact byte-string match at positions selected by an input mask?

Answer: the leaf returns false in `AL` when incoming
`ECX` is nonzero. Otherwise it compares the needle
against candidate starts `haystack + RSI + 1 + bit_index`.
When the low 16 mask bits contain any set bit, it visits
those bits in ascending order and returns true on the first exact match, false
after exhaustion. An empty needle returns true. If the low mask word is empty,
the machine still tries a single candidate at `tzcnt(EDX)`, including index
32 for an entirely empty dword under TZCNT semantics. This is
a comparison leaf with 0 callees; its answer does not depend on an
unbound helper.

## Target and extent

Target `node94`: `artifacts/node/94/hl-node`,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, size 91774280 bytes.
All addresses are linked ELF virtual addresses, without rebasing.
Window `0x1407ec0..0x1407fb0` is 240 bytes,
file offset `0x1406ec0`, body SHA-256 `76d2b7b814722c8c202960f2a5abc5b9cd7fa964545e8c141ad824da7b4d9a33`.
FDE `.eh_frame+0x7a70` has length field
16, CIE `.eh_frame+0x0`.
The following FDE starts at `0x1407fb0`: external padding is
0 bytes. Inside the body are 2
NOP instructions totaling 24 bytes. They are decoded
alignment fill, not skipped unknown instructions. Raw FDE/CIE records are in JSON.

The strict Python decoder accounts for 65 instructions,
64 reachable from entry, 17 branches and
2 return instructions. Every branch lands on a decoded instruction
within the FDE. All remaining body instructions are NOP fill. This combination
of decoded control flow, returns and actual FDE extent supports a complete leaf;
neither a comment seed nor the next unwind-table start alone defines its body.

## Instruction-derived observations

`instructions.txt` is the complete byte-addressed instruction walk, generated
by the strict opcode/ModRM whitelist in the tool. Operand suffixes give bit
widths. Unknown encodings, truncated operands and external branch targets fail.
The tool and tests never invoke an external disassembler.

The descriptor in RDI supplies a haystack pointer at
`+0`, a needle pointer at
`+16` and a byte length at
`+24`. The intervening descriptor field is not read.
RSI is an offset, not an independent pointer: the leaf adds the descriptor's
haystack base and the candidate bias. The descriptor and byte strings are read;
there are no memory stores, allocation, panics, indirect dispatch or calls.

For lengths below 4 bytes, the leaf uses explicit byte tests
with early success at each length boundary. Longer strings use
4-byte loads from the front and a final
4-byte load ending exactly at the needle end. For unaligned
lengths the final load overlaps the previous comparison. These loads cover the
whole string without extending past its end. Equality does not depend on byte
order because corresponding words are compared directly.

On a failed candidate, `rol ax, cl` rotates the all-ones-except-low-bit mask,
then `and dx, ax` clears the selected low-word bit. A zero result returns false;
otherwise TZCNT selects the next bit. The high mask word is therefore ignored
once any low-word candidate was present, even when all low-word candidates fail.
Only low-dword input guard/mask bits are inspected. A true result is established
only in AL; upper RAX bits retain scratch data and are not a canonical Boolean.

An initially empty low mask word is not checked before TZCNT. The rule above
records that behavior rather than silently assuming nonempty masks. TZCNT on
zero requires BMI1 semantics; on legacy BSF decoding that case has no defined
destination. Nonzero inputs have the same index under either instruction.
Invalid pointers, overlapping descriptors modified by another thread, and
address wraparound are outside the readable, non-wrapping model domain.

## Callers and first-party relationship

The complete 70370352-byte `.text` section beginning at
`0x1343c80` was scanned at every byte position for signed rel32
e8/e9 encodings targeting the entry. It produced 6 e8
sites, 0 e9 sites and 1 enclosing
FDE. All hits decode as calls at the ends of retained argument-setup contexts
in `callers.txt`. This supplies local instruction-boundary support; the complete
caller CFG has not been decoded.
The sites are `0x1403def`, `0x1403fd4`, `0x1404044`, `0x1404097`, `0x14040d2`, `0x1404141`.
Their common caller extent is `0x1403c30..0x14046cb`.
This is a direct-site census, not a census of indirect entry references or
proof that no interior entry is used. The caller's full behavior is not bound.

That caller loads Location `0x566ae58` at
`0x1404565` for the assertion `assertion failed: self.0 >= 0.`.
The Location's RELATIVE relocation points to the digest-bound historical
first-party source string with suffix `base/src/duration.rs` at
line 124, column 13. JSON records its bytes' hash and
length, source VA, raw Location, and relocation. The absolute historical build
prefix is deliberately not reproduced. This establishes a first-party call
relationship, not authorship: the leaf may be a monomorphized dependency helper.
The assertion call and its implementation are outside the leaf's callee closure.

## Novelty before writing this packet

Each command below returned exit status 1, empty stdout and empty stderr:

```sh
rg -i 1407ec0 research/
rg -i 21003968 research/
rg -i 1407ec0 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 21003968 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The lists were the supplied sibling copies. Their SHA-256 identities were:

- `../closed_unmerged_prs.txt`: `297dcbf46c25131b07f912c7b2af552d40f26be941156362395b7b5e3352ffbb`
- `../merged_prs.txt`: `efc5ab0523e72ecec68136b2c70a64c7c821829180eafe3d51be4bdc11fbe178`
- `../open_prs.txt`: `392b5dc45cbf7fd4c0a56640f566edbb28f31f2d5537cb364c99ad10dc62c496`

There are no callee behavior binds needing a separate novelty query. The check
is historical: rerunning it after adding this packet necessarily finds the packet.
Baseline repository revision: `e5c9b6436876b2a4a39daef813171f9879317699`.
The reference tree was not used as source; no imported evidence was changed.

## Reproduce and validate

Run from the repository root with Python 3.10 or newer, standard library only:

```sh
python3 tools/foundation_masked_compare.py --out research/work-items/RE-001-masked-compare-94/
python3 -m unittest tests.test_foundation_masked_compare -v
python3 research/work-items/RE-001-masked-compare-94/verify.py
make verify
make catalogue-check
```

The generator authenticates the whole binary before analysis, maps it read-only,
and regenerates semantic JSON, the instruction walks and this README. Manifest
paths are repository-relative; the verifier enforces an exact whitelist including
the tool, tests, ELF/FDE helpers and all packet files other than the manifest.
`--check` compares regenerated files byte-for-byte and checks the manifest.
Validation used Python 3.13.5. Exploratory
inspection used GNU objdump 2.44, -d -Mintel with bounded start/stop addresses; not a regeneration dependency. The committed instruction
walks come entirely from the Python decoder, with complete leaf coverage and
selected caller-context coverage. No decompilation or normalized comparison was used.

JSON contains 32 fixed instruction-derived vectors. Tests also compare
an independently written byte-string predicate with an interpreter of the decoded
instructions, exercising candidate order, overlapping final words, sparse masks,
early returns and noncanonical inputs. Invalid synthetic reads fail. These are
static semantic cross-checks, not observed execution results from the node.
Corruption controls attack the target digest, body bytes, FDE/CIE associations,
branch and call targets, Location relocation, census, generated text and manifest.
README counts are rendered from JSON and checked by the tests.

## Non-claims, limitations and next step

No captured binary was executed; no network or installations were used. No
normalization masks, native differential result, Rust build, source symbol,
dependency version or whole-node equivalence is claimed. No catalogue, progress
or acceptance gate changes are requested. The Python opcode semantics are
reviewable but are not an independent hardware oracle. The caller census does
not discover indirect calls, relocations to the entry or alternate interior entry.

Next step: bind the caller's descriptor construction and mask production to
identify the searched strings and prove its nonzero-mask/readability invariants.
That would connect this complete local comparison rule to a named node behavior.
