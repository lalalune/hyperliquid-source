# RE-001: tuple comparison with a saturating threshold (node #94)

Bounded question: what does `0x4d8c270` compute from its input object's
comparison fields, including equality, signedness and arithmetic overflow?

Answer: interpret the dwords at `+0x60/+0x64/+0x68` and
`+0x4524/+0x4528/+0x452c` as lexicographic tuples, comparing the first
field as signed and the remaining fields as unsigned. Let `current` be
the qword at `+0x28`, `base` the qword at `+0x10`, and `limit` the qword at
`+0x4408`. Return `2` in AL if `left >= right` and
`current >= limit`; otherwise return the Boolean `current >= sat_u64(base +
5000)` in AL. The function reads fields and returns without calls
or memory writes. RAX is not a canonical integer result: its upper bits
retain the last loaded tuple field on the early path or the saturated
threshold on the arithmetic path.

Task/component: RE-001 function map, with first-party L1 caller context.
This is a complete local integer rule, not recovery of the caller subsystem.
Intended added files: this packet, `tools/tuple_saturating_gate.py`, and
`tests/test_tuple_saturating_gate.py`. No existing files or gates change.

## Identity and extent

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; file size `91774280` bytes.
Source baseline commit: `e5c9b6436876b2a4a39daef813171f9879317699`.
No inferred reference source was used to author the model; no reference
revision or source-level function name is claimed.

| Field | Value |
| --- | --- |
| ELF VA interval | `0x4d8c270..0x4d8c2d8` (end exclusive) |
| File offset | `0x4d8b270` |
| Body SHA-256 | `eeb533203e237c62866162e4df9e237a0a04deab8028de004d5d941b9184e228` |
| FDE VA / section offset | `0xf48f20` / `0x267a08` |
| CIE VA / section offset | `0xce1518` / `0x0` |
| Following FDE start | `0x4d8c2e0` |
| Padding bytes | `cccccccccccccccc` |

| Metric | Count |
| --- | ---: |
| Function bytes | 104 |
| INT3 padding bytes | 8 |
| Decoded primary instructions | 29 |
| Callees | 0 |
| Direct e8 call patterns | 4 |
| Direct e9 jump patterns | 0 |
| Internal branches | 8 |
| Return instructions | 1 |
| Memory writes | 0 |
| Target-grounded vectors | 22 |

These counts come from `records.json`; tests compare this table and the
entire generated README with the records. The FDE's explicit range, complete
instruction decode, forward CFG with a shared RET, and INT3 gap jointly
support the extent. The following FDE is an extent boundary only; its
behavior is not bound. `frames.txt` retains raw records and CIE associations.

## Instruction argument

`instructions.txt` gives every primary instruction's address, bytes, decoded
operands and the caller excerpts. `records.json` contains semantic records,
not a duplicate per-instruction listing.

The initial MOV loads the first left dword; the following MOV loads `current`
unconditionally. CMP/SETL/JNE implements the signed first-field comparison.
On equality, CMP/SETB/JNE compares the next field unsigned. On equality
again, CMP/JAE compares the final field unsigned. The SET instructions
preserve flags, so the adjacent JNE still tests the preceding CMP.
The shared TEST path selects the tuple-less case. A tuple that is greater
or equal reaches MOV AL,2 and the unsigned qword
limit comparison; JAE returns that value directly.

The remaining paths load `base`. CMP against `0xffffffffffffec78`
selects whether adding `5000` can carry. Below that cutoff,
the addition cannot overflow. At or above it, ADD/CMOVB replaces a carried
sum with `0xffffffffffffffff`. MOV RDX does not overwrite carry. The final
CMP/SETAE compares `current` with that saturated threshold and changes only
AL. The decoded instructions therefore prove both the low-byte rule and
the residual upper RAX bits. `model()` independently states the rule;
`interpret()` follows decoded operations and flags. Boundary vectors compare
them, including short-circuit reads and the first overflowing base.

## Callees and incoming references

The callee list is empty, established by decoding the complete function.
There are no external jumps, indirect dispatch, constant-pool reads or
callee-identity/extent gaps for this function.

The census scans every byte of the complete `.text` section, start
`0x1343c80`, size `70370352`, for e8/e9 signed rel32
targets. It retains all matches without an alignment filter:

| Call site | Enclosing FDE interval |
| --- | --- |
| `0x4adf597` | `0x4adef10..0x4adf622` |
| `0x4ae041d` | `0x4adfe30..0x4ae062f` |
| `0x4c19272` | `0x4c18b40..0x4c1941f` |
| `0x4c19a2f` | `0x4c19420..0x4c19b62` |

All retained sites decode as direct calls in bounded argument/consumer
excerpts. Those excerpts show callers consuming AL, including comparisons
with the early-return value. Caller FDEs are parsed and cross-checked against
the unwind index. This is a complete byte-pattern census, not a proof of
reachability of whole caller CFGs or a census of indirect/data references.
No negative claim about such other references is made.

The caller `0x4c19420` also contains a RIP-relative LEA at
`0x4c19b52` referencing the Location at `0x5742320`.
The Location's relocated path resolves to first-party source suffix
`l1/src/books.rs`, line `14`, column `16`.
The path pointer is resolved through its actual R_X86_64_RELATIVE record,
not by treating a zero on-disk pointer as a loaded pointer. The packet
retains hashes and a relative source suffix to omit the captured build
account/path prefix. This is evidence of first-party caller context; it
does not identify the leaf's original source file, name, or field types.

## Novelty before packet creation

At the source baseline above, each command returned exit status `1` with
empty stdout and stderr (no matches):

```sh
rg -i '4d8c270' research/
rg -i '81314416' research/
rg -i '4d8c270|81314416' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The sibling PR-list copies were byte-compared with the supplied shared
baseline copies. Their SHA-256 identities were:

| List | SHA-256 |
| --- | --- |
| open_prs.txt | `392b5dc45cbf7fd4c0a56640f566edbb28f31f2d5537cb364c99ad10dc62c496` |
| merged_prs.txt | `efc5ab0523e72ecec68136b2c70a64c7c821829180eafe3d51be4bdc11fbe178` |
| closed_unmerged_prs.txt | `297dcbf46c25131b07f912c7b2af552d40f26be941156362395b7b5e3352ffbb` |

There are no callee behavior binds needing a separate novelty search.
The selected entry is in the assigned address band and is not an excluded
address. The research search predates this packet, which now necessarily
contains its own address. This is an address-novelty result, not a claim
that no other function computes an analogous rule.

## Reproduction and controls

From the repository root, Python 3.10+ stdlib only:

```sh
python3 tools/tuple_saturating_gate.py --out research/work-items/RE-001-tuple-saturating-gate-94/
python3 -m unittest tests.test_tuple_saturating_gate -v
python3 research/work-items/RE-001-tuple-saturating-gate-94/verify.py
make verify
make catalogue-check
```

The tool reads a single mmap of the target, verifies the full pinned digest
before parsing, regenerates deterministic evidence, and checks exact
whitelisted packet content. The manifest also covers the tool and tests.
Wrong target/body identities, bad instructions, shifted FDE metadata,
retargeted incoming calls, altered rule/callee records, padding corruption,
and packet/manifest edits must be rejected. Tests compare the independently
authored model with the decoded instruction model across signedness and
saturation boundaries. These are static checks, not runtime differential
tests. No captured executable is run. No normalization masks are applied.

Analysis used CPython 3.13.5 and focused GNU objdump 2.44 inspection during
candidate selection only. The committed tool, verifier, tests and generated
disassembly do not invoke or require objdump. No connected REA provider was
available; make doctor reported static analysis readiness and no Ghidra.
No installation, network, hosted CI or container result is claimed.

Observed validation: packet generation, the targeted unittest suite, packet
verification, `make verify`, and `make catalogue-check` passed. A supplementary
`make test` run reported an existing timeout in
`test_bridge_inventory.ArtifactTests.test_external_artifact_is_portable_and_still_digest_checked`
and was subsequently interrupted. That repository-wide run is failed and
incomplete, not a passing validation result; no unrelated files were changed.

## Assumptions, limitations and next step

The model assumes valid readable memory for every accessed field, stable
field contents during the call, and ordinary x86-64 integer execution.
Invalid pointers may fault; there are no explicit pointer or range checks.
It preserves the observed short-circuit reads; a skipped field need not be
readable on that path. It models the return value and field reads, not all
scratch-register/flag values or machine fault delivery.

No source-level type names, units for the addend, enum/Option interpretation,
or business meaning are established. In particular the byte result must not
be advertised as a canonical full-register integer. The binary's apparent
first-party caller context is not proof of exclusive first-party ownership.
No independently compiled Rust fragment, matched bytes, full-node build,
whole-ELF equivalence or full-scope acceptance gate is claimed.

Next step: follow the caller's object construction and stores to the compared
fields to establish their units and the meaning of the early-return state,
without assigning source names from the arithmetic alone.
