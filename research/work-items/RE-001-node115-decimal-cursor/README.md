# RE-001: node #115 consuming decimal cursor

- Component/task: RE-001 function map; transport dependency parsing lead for RE-012.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `05bc2de303c05525b71e7e257426e741bc66a390`. New rule/model/docs are independently authored under the root MIT license. Decoder, mapping and scan helpers adapt existing MIT repository code. No upstream source implementation or inferred unlicensed source is copied; no upstream revision is attributed.
- Bounded question: What packed result and cursor mutation does this complete leaf compute from a bounded byte stream?

**Answer.** With valid, stable, disjoint state and buffer memory, RDI points to a
state whose end pointer is at `+8` and cursor at `+16`. The leaf consumes a prefix
of up to three bytes. Each consumed byte advances the stored cursor before its
ASCII digit check. Exhaustion before three valid digits returns RAX `0x30001`;
the first non-digit returns `0x30002`, including that byte in consumption. Three
valid digits, including leading zeros, return their decimal value shifted left
by sixteen bits. Bytes after that prefix are untouched. No failure rolls back
the cursor. These are raw machine results, not recovered Rust enum names.

## Window, ownership and counts

All coordinates are original ELF VAs unless explicitly marked file offsets.
The complete window is `[0x2e564b0, 0x2e56538)`, size
136 bytes, file offset `0x2e554b0`. The FDE is at
VA/file offset `0xd9aac4`, CIE `0xca6ed8`,
with `zR` augmentation, PC-relative signed-word encoding and no LSDA.
The body SHA-256 is `1a8232ce726e9ffed03a2c18b4a551a07c2f24be62c92791b09e5304dcb90ae6`. Actual FDE extent, complete
instruction coverage, all branch destinations and returning paths agree.
The following `cccccccccccccccc` padding occupies
`[0x2e56538, 0x2e56540)`; it is excluded from the body.
FDE bounds alone are not used as a whole-program function census.

Every reported count below is generated from `records.json` and checked by the
targeted tests. No component/function-coverage denominator is claimed.

<!-- counts:start -->
- body_bytes: 136
- callees: 0
- conditional_branches: 6
- cursor_stores: 3
- direct_call_sites: 1
- direct_caller_owners: 1
- frozen_vectors: 18
- instructions: 42
- padding_bytes: 8
- returns: 2
- tail_jump_sites: 0
- targeted_tests: 18
- text_bytes_scanned: 83719936
<!-- counts:end -->

The leaf has no CALL, external jump, indirect dispatch, RIP-relative data load,
or helper dependency. Its callee set is empty; callee identities/extents and
callee-target controls are therefore inapplicable. Incoming call displacement
corruption is tested instead. `instructions.txt` and the JSON retain every
instruction's raw bytes, decoded operands and address. The CFG covers the entire
body with no unexplained internal padding or unreachable instructions.

## Instruction proof

- Entry loads end into R8 and cursor into RDX. EAX initially holds `0x30001`.
  Unsigned `cursor >= end` returns it without reading a buffer byte or storing
  the cursor. An already exhausted cursor is allowed by this raw rule.
- At `0x2e564c2`, `0x2e564da` and `0x2e564f5`, MOVZX loads successive bytes.
  The stores at `0x2e564c9`, `0x2e564e2` and `0x2e564fe` write initial cursor
  plus one, two and three respectively, before validating the loaded byte.
  Bounds checks before the latter loads keep the incomplete return distinct
  from an invalid byte. State `+0` is never accessed.
- The first and last bytes add `0xd0` modulo the byte width, equal to subtraction
  of ASCII `0`. The middle byte uses LEA with `-0x30`, then compares its low byte.
  Unsigned `>9` or `>=10` rejects exactly the complement of ASCII `0` through `9`,
  including bytes below `0`, high bytes, signs, whitespace and NUL.
- On the valid path, `0x2e56514` multiplies the first digit by `100`. The middle
  byte remains its original ASCII value in SIL. MOVZX, doubling and LEA multiply
  it by `10`; `add cl,0x20; movzx ecx,cl` produces
  `(10*(48+d)+32) mod 256 = d*10` for every digit d. This byte truncation is
  essential to explaining the apparent ASCII rather than digit multiplication.
  The last digit is added, and SHL by `16` packs the decimal value in EAX.
  Its maximum is `999`, so neither the sum nor packing overflows the result word.
  All exits follow a write to EAX, establishing zero in RAX's upper half.

The independent `model()` implements decimal accumulation and cursor mutation.
`instruction_value()` separately expresses the decoded byte arithmetic and its
extracted constants. Frozen vectors and exhaustive valid decimal triples agree;
byte substitutions at every position check the full admission alphabet.
Real factor, admission and packing operand mutants change this relation before
the validator rejects them. These checks are static formulas, not target
execution, an emulator or a runtime differential test.

## Caller census and source evidence

The producer scans every possible byte position in full `.text`
`[0x1419300, 0x63f0a00)` for E8/E9 signed rel32 destinations equal
to the entry. It retains unaligned hits rather than assuming opcode alignment.
The sole hit is `CALL` at `0x2e57e92`, in actual caller FDE
`[0x2e57c60, 0x2e5810f)`, FDE
`0xd9ac40`, CIE `0xca6ed8`. The retained local decode
from `0x2e57e7a` passes a stack-state address in RDI, calls the leaf,
shifts the returned word right by `16` and compares AX with `2`.
This corroborates a packed value/status split. It does not recover the entire
caller CFG, prove entry reachability, or rule out indirect callers or references
outside `.text`. The census is complete for the stated byte-pattern scan only.

Inside that same caller FDE, LEA at `0x2e57f81` addresses Location
`0x6453d88`. Its actual R_X86_64_RELATIVE relocation targets
`0x446fcd`; the metadata gives `z_vendor/httparse/src/iter.rs` at
line 88, column 9. The complete original path
bytes are authenticated by `d16979a23d4e57a0f42ddc294f588c5cc82e508f0a61aafde39e7b30bba13b4b`; its build-machine prefix
is omitted from committed prose/data. The raw Location and relocation are
retained. This supports a vendored httparse association, not first-party
Hyperliquid authorship or an exact dependency revision. The leaf itself has no
source Location. Small first-party-associated leads examined during discovery
were dispatchers or close variants of existing binds; this dependency parser
instead adds an unbound consumption/error contract useful to transport work.

## Novelty

Before creating this packet, these commands produced empty stdout and exit
status 1 for each search (no matches). There are no bound callee addresses.
The snapshot checked was the recorded source base plus the supplied PR lists;
this is not a claim about later upstream submissions.

```sh
rg -i '2e564b0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg '48587952' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'decimal-cursor|decimal_cursor' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The existing three-digit-decimal packet describes a different pointer/length
leaf that rejects leading zero and has no consuming cursor. It is background,
not evidence for this function's behavior. No existing work item/tool/test is
modified and no progress/catalogue/gate record is changed.

## Reproduce and validation

From repository root, with materialized authenticated inputs, Python 3.10+
stdlib and the existing ELF/FDE parsers:

```sh
python3 tools/node115_decimal_cursor.py --out research/work-items/RE-001-node115-decimal-cursor/
python3 -m unittest tests.test_node115_decimal_cursor -v
python3 research/work-items/RE-001-node115-decimal-cursor/verify.py
make verify
make catalogue-check
```

Development environment: Linux x86-64, Python 3.13.5. GNU objdump 2.44 was used
only for bounded exploratory inspection. The producer, verifier and tests never
import or invoke it. Their evidence comes from strict Python decoding. No
network, installation, captured executable, private fixture or emulator is used.
A single memory map avoids a second full binary copy. Public generation checks
the complete digest before parsing or output creation.

`verify.py` enforces an exact file/manifest whitelist, binds the tool, tests and
parsing dependencies, and compares regenerated payloads byte for byte. Controls
cover every body byte, malformed/truncated instructions, wrong digest, shifted
FDE/extent, CIE, padding, incoming call target, caller interpretation, Location
metadata/path/relocation, and extra/duplicate/missing/symlinked manifest files.
README metrics are checked against JSON and their underlying evidence arrays.
The producer, targeted tests, packet verifier, `make verify` and `make reproduce`
passed locally. `make catalogue-check` failed on pre-existing root README
work-item inventory drift, confirmed before this packet was tracked. Generated
files are unchanged under the add-only task constraint. Repository-wide
`make test` is intentionally omitted under the task's validation limit.

## Results, non-claims and next step

Before: no retained research or supplied PR-list reference to this entry.
After: a complete local value/consumption contract, caller census, extent and
source association can be regenerated from authenticated bytes. Verdict:
**strong for this bounded raw result and cursor contract**.

No original Rust function name/type/ABI, exact httparse version, HTTP status
policy, delimiter consumption, incremental-parser rollback, whole caller,
all-caller reachability, pointer safety or protocol compatibility is claimed.
Arbitrary invalid pointers, aliasing state/buffer, concurrent mutation and
wrapping pointer arithmetic are outside the stated memory contract. The leaf
is instruction-complete, while caller/source context is explicitly range-limited.

Rust implementation, Cargo closure, build flags, two-build comparison, normalized
source comparison, runtime differential evidence and whole-ELF equivalence are
not yet implemented/measured. Normalization masks: none. There is no local
helper/vtable/relocation dependency in the leaf; only the cited caller Location
relocation is bound, with all wider data/unwind/caller closure left open.
No full-scope gate is requested; reconstruction remains incomplete.

Next: bind the caller's handling of the returned status and saved cursor to
establish when incomplete parsing resumes or rolls back and what delimiter must
follow a successful decimal prefix.
