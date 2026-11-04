# RE-001: node #115 ring-range projection

- Component: consensus-associated container projection; RE-001 with an RE-008 lead.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No external source implementation used.
- Claim: observed complete leaf computation; circular-buffer interpretation is inference.
- Bounded question: which pointer endpoints does this function compute from its input words?

Given unsigned words C, P, H, L at input offsets +0, +8, +16, +24, an empty
L writes [P,P,P,P]. Otherwise it reduces H by C **once** if H >= C, producing h,
and computes t = (C-h) modulo 2^64. If L > t (unsigned), the output is
[P+408*h, P+408*C, P, P+408*(L-t)]; otherwise it is
[P+408*h, P+408*(h+L), P, P]. Every output address calculation wraps modulo
2^64. The function writes these words through incoming RDI and returns that
same pointer in RAX. Incoming RSI supplies the input. It calls no helper.

## Scope and bytes

The window is ELF VA `[0x24cdad0,0x24cdb3f)`, file offset `0x24ccad0`.
Body SHA-256: `3b3f546c00ba1a4b6c071c172de25d7e15f722131d4301739bd098f62702c905`. The FDE is at VA/file offset `0xd18a84`,
CIE at `0xca6ed8`, augmentation `zR`, no LSDA. Actual FDE range, complete
instruction decoding, local branch closure, terminal RET and neighboring INT3
padding agree. The FDE is corroborating metadata, not the sole boundary proof.
Neighboring bodies are not bound. No normalized byte masks are used.

Every measured count below comes from `records.json`; the targeted test checks
this table against the JSON and against the underlying arrays/ranges.

| Metric | Count |
| --- | ---: |
| function_bytes | 111 |
| instructions | 34 |
| callees | 0 |
| direct_call_sites | 4 |
| caller_fdes | 4 |
| direct_tail_jump_sites | 0 |
| source_locations | 3 |
| vectors | 14 |
| padding_before | 10 |
| padding_after | 1 |

`records.json` contains the unnormalized body bytes, every decoded instruction,
FDE/CIE records, padding, caller windows and source-location relocation records.
There is no hidden native-disassembler dependency. The purpose-built strict
Python decoder handles only the forms used in this packet and rejects unknown
or truncated instructions; it does not claim to decode the whole ELF.

## Instruction proof

- `0x24cdad0..0x24cdadc`: preserve the output pointer, load L, and branch on
  zero before reading C or H. The empty arm zeroes the indices.
- `0x24cdadc..0x24cdaef`: load C and H; unsigned CMP/CMOVAE chooses C or zero
  for a single subtraction. This is not a general modulo operation.
- `0x24cdaef..0x24cdafd`: compute t in R9, subtract it from L in RDI, then
  JA selects wraparound exactly when there was no borrow and the difference
  was nonzero. Equality follows the contiguous arm.
- `0x24cdafd..0x24cdb0d`: the contiguous arm sets the first end index to h+L
  and the second to zero. The wrap arm retains C and L-t. The empty arm sets
  all indices to zero. Every branch targets a decoded instruction in this body.
- `0x24cdb0d..0x24cdb3f`: load P, multiply the indices by the immediate 408,
  add P, write the endpoints and return. IMUL retains the low word; signedness
  does not change that product modulo 2^64, and its overflow flags are unused.

All input loads precede every output store. This leaf reads no element payload,
allocates nothing, changes no input word except if it aliases the output, and
contains no indirect transfer, call, panic edge, or unclosed helper. On the
empty path it reads only L and P. Normal completion assumes readable required
input bytes, writable output bytes, a valid return stack and stable memory;
invalid pointers, concurrent mutation and hardware faults are outside the rule.
Output endpoints need not be dereferenceable for the leaf to compute them.

Under the additional ring interpretation (C > 0, h < C, L <= C and an adequate
allocation without address wrap), these endpoints represent the logical items
as a first range from the head toward the allocation end and a second range
from its base. The lengths add to L, and crossing the allocation end introduces
the second range. Empty input canonicalizes all endpoints to P. The raw-word
rule also covers invalid ring geometry: H >= C is reduced only once and the
tail subtraction can wrap. The frozen vectors deliberately include these
cases, the unsigned comparison boundary, and multiplication/address overflow.

## Callers and first-party association

The complete `.text` interval `[0x1419300,0x63f0a00)` was scanned at every byte
for E8/E9 plus signed rel32 targeting this entry. The retained hits are direct
CALL encodings at `0x2e0ec44`, `0x2e150ee`, `0x2e182a3`, `0x2e1f344`.
Each decodes on an instruction boundary in its retained local setup/readback
window, and every window lies in the recorded actual caller FDE. The readback
loads all output words immediately after CALL. This establishes syntactic
local call evidence, **not** complete caller-CFG validation or runtime
reachability: an all-byte scan can in general match data/immediates. Indirect
callers, other executable sections and dynamic targets are unmeasured.

Selected RIP-relative LEAs in enclosing caller FDEs resolve to relocated
Location records naming `node/src/consensus/state.rs:550:17` and
`node/src/consensus/mempool.rs:516:38`, `:809:14`. Actual RELATIVE entries,
string bytes/lengths and Location fields are checked. These are relative paths
already embedded in the target, not workstation paths. The association applies
to the enclosing FDEs, not necessarily the call's source line. No original
symbol, concrete container type, element identity or consensus behavior is
assigned. The remaining enclosing caller has no first-party attribution here.

## Novelty and ownership

Before writing this packet or investing in the bind, from repository root:

```sh
rg -i '24cdad0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '38591184' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Both commands produced empty stdout and exit status 1. There are no outgoing
callees whose behavior needs an additional novelty check. Repeating these
commands after adding the packet will naturally find this packet itself.
The selected entry is inside the assigned address band and outside all supplied
claimed addresses. Only this work item, its new producer and new tests are in
scope; the caller windows are association evidence, not additional function binds.

## Reproduce and controls

From repository root, with the authenticated artifact materialized:

```sh
python3 tools/node115_ring_ranges.py --out research/work-items/RE-001-node115-ring-ranges/
python3 -m unittest tests.test_node115_ring_ranges -v
python3 research/work-items/RE-001-node115-ring-ranges/verify.py
make verify
make catalogue-check
```

Python 3.13.5 on Linux was used; the producer, verifier and tests require only
Python 3.10+ stdlib and the existing stdlib ELF/FDE readers. GNU objdump 2.44 was
used for exploratory inspection; no committed result or reproduction step
requires it. Static only: no captured node/visor execution, emulator, network,
installation, chain action or GitHub action. A single memory map avoids copying
the full binary. `make doctor` and initial `make verify` passed.

The producer authenticates the complete target before parsing or creating
outputs. The verifier requires an exact manifest whitelist, verifies file
hashes, then regenerates and byte-compares the semantic JSON and README.
Tests include whole-target digest failure, a body mutation below the digest
gate, shifted/extended FDEs, branch/stride/input-offset mutations, a redirected
incoming CALL, altered Location relocation/data, padding damage and unsupported
or truncated decoder input. There is no outgoing callee to retarget: the actual
incoming call target is the meaningful negative control. Frozen vectors and an
independent ring-index oracle exercise the rule without running machine code.

## Implementation, limitations and next step

Before this packet, the novelty search found no retained bind for the entry.
After it, the complete byte-backed word relation and conditional ring-range
meaning are reproducible. The small Python model is independently authored;
no inferred source text was copied. New files use the repository MIT license.
No Rust implementation, Cargo graph, compiled comparison, two-build result,
relocation-normalized match, full unwind semantics or original ABI is claimed.
The model tests establish consistency with the decoded rule, not dynamic
behavioral equivalence. No inventory/literal catalogue or progress gate changes.
Repository-wide tests, hosted CI and container builds are not claimed.

Next step: establish the input object's producer and its ring invariants in a
consensus/mempool caller, including the identity and lifetime of its elements,
before using this projection in a reconstructed state path.
