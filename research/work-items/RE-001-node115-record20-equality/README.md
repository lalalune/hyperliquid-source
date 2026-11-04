# RE-001: node #115 20-byte record equality

- Component: RE-001 function map; potential serialization/consensus use unproven.
- Target: node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base revision `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No external source is used.
- Bounded question: what predicate does the function at `0x5429440` compute for its two input pointers and record count?
- Answer: given two readable, valid sequences of `count` consecutive 20-byte records, it returns AL=1 exactly when all corresponding bytes are equal, and AL=0 at the first unequal record. Count zero returns AL=1 without dereferencing either pointer. The function has no calls and writes no input memory. The original type and application meaning are unknown.

## Evidence and interpretation

ELF virtual-address window `0x5429440..0x5429493` is 83 bytes at file offset `0x5428440`, body SHA-256 `c8ac9cd7f46953738745e63aee0e82ec7a35c1e6ccd0fa715ab1f0dea80f3010`. Its actual FDE at `0xf7d1a8` references CIE `0xca6ed8` (`zR`, PC-relative signed 4-byte encoding), with no LSDA. The 13 bytes from `0x5429493` to `0x54294a0` are `cc` padding; they are outside the FDE. FDE and terminating control flow support this local extent; FDE alone does not prove a source-level boundary. The full 24-instruction byte walk, branch destinations and original FDE bytes are in `records.json`.

RDI and RSI address the records; RDX is the count. The zero test branches to `mov al,1; ret`. For each nonempty record, two unaligned 16-byte loads and `pcmpeqb` compare offsets 0..15. The two `movd` instructions load offsets 16..19 and zero their upper 12 SIMD bytes; a second `pcmpeqb` therefore produces equal upper lanes and compares the final four in its low lanes. AND combines those lanes with the first comparison, and `pmovmskb` equals `0xffff` iff all 20 bytes match. The register decrement and carry track remaining records; a mismatch returns immediately, while matching records advance both pointers by 20. The final matched record returns one. This is a static all-input argument, not a captured execution or an assertion about the rest of RAX.

There are 0 callees in the complete instruction walk. The full `.text` scan for `e8`/`e9` plus signed rel32 finds 2 candidate sites: `0x4e09521` (call) and `0x4e09549` (tail jump). They are actual instruction starts in their enclosing FDE `0x4e08ed0..0x4e09953`; the nearby preceding comparisons check the two input lengths before each site. The raw scan checks every byte offset and can contain false positives; indirect references and code outside `.text` are excluded, so it is not a whole-program caller census. This observation does not identify the records' type or owner.

## Novelty and reproduction

The following commands returned no matches before selection (hex is case-insensitive):

```sh
rg -i '5429440|88249408' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, Python 3.10+ and standard library; no disassembler is used by these commands:

```sh
python3 tools/node115_record20_equality.py --out research/work-items/RE-001-node115-record20-equality/
python3 -m unittest tests.test_node115_record20_equality -v
python3 research/work-items/RE-001-node115-record20-equality/verify.py
make verify
make catalogue-check
```

Generation authenticates the full artifact and verifies the FDE, exact instruction encodings, branch targets, padding and all raw direct-relative candidates. The independent Python value model and tests cover zero, single/multiple records, every byte position and corruption below the identity gate. Discovery used GNU objdump 2.44, but retained generation and verification use strict Python decoding. No binary was executed, no native source was copied, and no source build, normalized comparison or implementation equivalence is claimed. Original compiler flags, relocations, indirect references, caller reachability, object layouts and fault behavior are unresolved. Valid readable buffers and non-wrapping pointer arithmetic are prerequisites; invalid pointers and concurrency are outside this claim. No full-scope progress gate is requested.

Next: identify the enclosing caller's record types and their provenance using independent data and caller evidence.
