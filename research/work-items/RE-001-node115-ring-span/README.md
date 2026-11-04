# RE-001: node #115 ring-span descriptor at 0x2d55b30

Task: RE-001 function bind. Component allocation: `assets`,
based on the asset/pdi caller context. This is bounded static research, not a
reconstructed Rust component or gate claim.
Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code and prose are independently
authored under the repository MIT license; no inferred proprietary source was copied.

## Question and answer

**How does this leaf transform four input qwords into its returned nine-qword descriptor?**

Given input qwords `(a,b,c,d)` at RSI and output at RDI, this call-free leaf returns
the original output pointer in RAX after writing the descriptor below. For
`a != 2^63`, it forms a ring-shaped split with a 48-byte element stride,
reduces the starting index by **at most one** subtraction of `a`, separates the
non-wrapping and wrapping portions, and writes pointer endpoints plus a residual
count with raw tag `2`. Empty input produces empty spans at `b`.
For `a == 2^63`, it instead writes an alternate descriptor controlled by whether
`b` is zero. The sentinel is established by **NEG overflow**, not a sign test.
Every store and control-flow edge is decoded; no helper behavior is assumed.

## Rule and proof

All variables below are unsigned qwords, with addition, subtraction and address
multiplication modulo `2^64`. These equations cover raw input words; native
memory validity remains a precondition. The original types and field names are
unknown. The words “capacity”, “head” and “span” describe an inferred use of the
observed arithmetic, not recovered source identifiers.

For the ordinary arm, if `d == 0`, set `i = e = k = 0`. Otherwise:

```
i = c - (a if c >= a else 0)
room = a - i
if d > room: e = a;     k = d - room
else:        e = i + d; k = 0
P(x) = b + 48*x
output = [2, P(i), P(e), b, P(k), 0, P(e), b, k]
```

For the sentinel arm, let `f = int(b != 0)`:

```
output = [f, 0, b, c, f, 0, b, c, (d if f else 0)]
```

The instruction walk is retained in `instructions.txt` and in `records.json`.
At `0x2d55b39`, qword NEG sets OF only for the bit pattern `2^63`; JNO selects
the ordinary arm for all other words, including other high-bit-set words.
The sentinel arm's TEST/SETNE observes the full `b`, zero-extends the flag by
XOR EDI followed by MOV DIL, and avoids reading input `+0x18` when `b == 0`.
The ordinary arm tests `d` before loading `c`; an empty span ignores `c`.
CMP/CMOVAE at `0x2d55b72` performs unsigned `c >= a`; the subsequent subtraction
reduces `c` once. The SUB at `0x2d55b85` and JA use unsigned **strict** `d > room`;
equality takes the contiguous arm with zero residual count. Each LEA computes
three times its index and each SHL multiplies by sixteen, giving the stride.
The stores at `0x2d55bc7` onward cover every output word, with duplicate endpoint
words preserved. RET ends the FDE, with no outgoing branch, call or indirect dispatch.

For `a > 0`, `c < 2*a`, `d <= a`, and valid non-wrapping addresses, these are two
ordered contiguous spans of a circular buffer, with total element count `d`.
This useful interpretation is narrower than the raw-word equation. For example,
`c >= 2*a` is not normalized modulo `a`; raw arithmetic still follows the equation.
The model does not validate allocation geometry or dereference calculated endpoints.
Input reads precede all output stores, so the local equation also permits overlapping
input/output storage if those accesses themselves are valid. Code and the live return
slot must remain intact. It makes no concurrent mutation or hardware-fault guarantee.

## Extent, caller context and closure

Coordinates are original ELF virtual addresses; the function is
`[0x2d55b30, 0x2d55bef)`, file offset `0x2d54b30`.
Body SHA-256: `e9a031557c0d127ca9671c407e03a7df2d07c693b016d4931703504e53455df2`.
FDE VA/file offset `0xd94580`; CIE VA/file offset `0xca6ed8`.
Raw FDE/CIE bytes and LSDA absence are retained. The complete decoded graph is
acyclic, every instruction is reachable in its structural graph, and its only
exit is RET. This validates this particular extent beyond an unwind start alone.
Padding is `cc` at `0x2d55bef`, up to the next FDE start `0x2d55bf0`;
it is excluded from the body digest. No callee identity/extent is outstanding:
the measured leaf has no calls or external transfers and no RIP-relative data reads.

The full `.text` interval `[0x1419300, 0x63f0a00)` was scanned at every
byte for E8/E9 signed-rel32 destinations. The retained matches are E8 calls at
`0x2c47db2`, `0x2c47e05` and `0x2c4820c`, all within caller FDE
`[0x2c47660, 0x2c4d2e9)`. Argument-setup slices are decoded from
their bytes and end at these calls; output is a stack address and input is moved
into RSI. Their owner FDE references a relocated Location at `0x644d990`
from LEA `0x2c4c715`, pointing to `l1/src/asset/pdi.rs:32:14`.
The path, length, line, column and R_X86_64_RELATIVE addend are checked.
This binds a first-party **caller context**, not an original leaf name or proof
that this potentially generic monomorphized operation was authored in that file.
No absolute build-machine path is recorded.

The census is exhaustive for raw E8/E9 destinations in the stated interval.
Local instruction slices support the matches, but the complete caller CFG is
unmeasured; indirect calls, function pointers, dynamically modified code and
callers outside `.text` are not counted. Caller behavior and its own callees
are not bound. There are no normalized code bytes or masked operands.

## Derived counts

This entire block is rendered from `records.json`; the test suite checks it and
the complete README rendering against the JSON. Counts measure only this packet.

<!-- counts:start -->
- body_bytes: 191
- call_sites: 3
- callees: 0
- caller_owners: 1
- conditional_branches: 4
- instructions: 58
- output_words: 9
- padding_bytes: 1
- returns: 1
- tail_jump_sites: 0
- text_bytes_scanned: 83719936
- unconditional_branches: 2
- vectors: 14
<!-- counts:end -->

## Novelty before analysis

Before adding this packet, these commands all returned exit status 1 with empty
stdout and stderr at the source base above:

```sh
rg -i '2d55b30' research/
rg -i '47536944' research/
rg -i '2d55b30' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '47536944' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees needing additional novelty checks. The start lies in the
assigned `[0x2800000,0x3c00000)` band and is absent from the supplied claimed-address
list. After creation, the research searches naturally match this packet. The
external title lists are preflight inputs, not a claim of a live upstream query.

## Reproduce and validation scope

From the repository root, with materialized authenticated target bytes:

```sh
python3 tools/node115_ring_span.py --out research/work-items/RE-001-node115-ring-span/
python3 -m unittest tests.test_node115_ring_span -v
python3 research/work-items/RE-001-node115-ring-span/verify.py
make verify
make catalogue-check
make reproduce
```

Local results: the targeted tests, packet verifier, `make verify`,
`make catalogue-check`, `make doctor` and `make reproduce` passed. Repository-wide
`make test` was not run, as requested. Hosted CI was not run or claimed.

The producer authenticates the whole ELF before parsing or output creation and
uses a single memory map, never a second full binary copy. Python 3.10+ stdlib
and the existing `elf_index.py`/`fde_extents.py` parsers suffice. Development
used Python 3.13.5 on Linux x86-64; exploratory GNU objdump 2.44 was used only
for manual inspection. No producer, verifier or test imports or invokes objdump.
The retained evidence is generated by the strict Python decoder. No captured
binary or emulator was run, and no network, installation or external service was used.

`verify.py` checks an exact file whitelist and manifest, regenerates all evidence
in memory, and requires byte-identical output. The manifest binds the producer,
tests, verifier and reused parsing dependencies as well as the generated packet.
Corruption controls cover the public digest gate, every byte of the local body,
truncated/unsupported instructions, shifted FDE, padding, actual caller targets,
Location references/data/relocation, and extra/duplicate/missing manifest entries.
A stride-operand counterfactual changes a model output before semantic rejection.
Frozen instruction-derived vectors cover sentinel, unsigned, empty, equality,
wrap, single-subtraction and modular-address boundaries; wider independent tests
compare valid ring spans with enumerated circular positions. Neither is target
execution. This tool only resolves the selected binary unknown; no surrounding
analysis infrastructure was changed.

## Results, limitations and next step

Before: no retained research/title-list reference to this function start. After:
its full local input/output rule, branch conditions, extent and direct-call
context are byte-bound and reproducible. Verdict: **strong for the raw-word
transformation**, with only an inferred circular-span/type interpretation.

No reconstructed Rust, Cargo graph, two-build comparison, whole-ELF equivalence,
runtime differential result, protocol meaning, memory safety, complete caller
reachability, original Rust ABI/type identity or component gate is claimed.
Source-implementation comparisons, relocation/vtable closure outside the stated
Location, and transitive caller semantics are not yet implemented/measured.
All existing progress/catalogue/gate records are unchanged. Next: bind a consumer
of this descriptor in the same caller to identify the raw tags' iteration and
ownership meaning before assigning an original collection type.
