# RE-001: bind node #94 asset-name scanning at 0x2786530

Task: RE-001; research allocation: dex-registry. Claim: complete leaf behavior,
with bounded caller context. No reconstruction or completion gate is requested.

## Bounded question and answer

Which characters stop this scanner, what does AL return, and where is its
cursor left? Given an iterator holding current/end pointers to a valid UTF-8
suffix, the function consumes scalars until it finds a character outside
ASCII `A–Z` and `0–9`, then returns `AL=1` with the current pointer immediately
past that character. Exhaustion returns `AL=0` and leaves current equal to end.
Empty input therefore returns false. Only the current-pointer field is written;
the end field is preserved. This is an invalid-character search, not an
uppercasing operation. The caller's error text identifies its asset-name use.

## Target, boundaries, and scope

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (authority: `provenance/artifacts.json`).
Repository baseline: `e5c9b6436876b2a4a39daef813171f9879317699`. Pinned reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`; reference source was neither consulted nor copied.
The catalogue's unverified comment seeds were inspected only for selection and
overlap. The selected start is inside the required `[0x2000000,0x3000000)` band.

All addresses are ELF virtual addresses unless explicitly called file offsets.
The function is `[0x2786530,0x27865fc)`, file offset `0x2785530`.
Its body SHA-256 is `b40e4a821b07be8b4c4905cc2377f7bd408287c129ff5b599832357b34e92c80`. The actual FDE is at
`.eh_frame+0xa4cdc`, with CIE at
`.eh_frame+0x0`. It has no LSDA. The next FDE
starts at `0x2786600`; the intervening bytes are exclusively `cc` (`int3`).
`records.json` retains the FDE/CIE hashes, record lengths, next-FDE identity,
branch edges and section mapping. Complete decoding reaches the recorded end,
all branch targets land on instruction boundaries inside the body, and all
instructions are reachable. FDE boundaries alone were not used as proof.

<!-- counts:start -->
| Measurement | Count |
| --- | ---: |
| body_bytes | 204 |
| padding_bytes | 4 |
| decoded_instructions | 60 |
| internal_nop_bytes | 15 |
| branches | 9 |
| returns | 2 |
| callees | 0 |
| direct_e8_callers | 1 |
| direct_e9_candidates | 0 |
| caller_slices | 3 |
| vectors | 16 |
| scanned_text_bytes | 70370352 |
<!-- counts:end -->

Counts above come exclusively from `records.json`; the tests compare this
whole table with the JSON. Sizes describe this selected leaf and the scan
scope, not a component denominator. The instruction count includes the internal
NOP and excludes external padding. Callee identities/extents form an empty
set: this function neither calls nor tail-transfers outside its own body.

## Instruction-derived rule

`instructions.txt` is generated entirely by the strict Python decoder and
contains every instruction byte in the leaf, plus the explicitly scoped caller
slices. Its body walk is:

- Entry loads current from `[RDI]` into R8 and end from `[RDI+8]` into RAX.
  Equality is tested at `0x2786572`; the empty path reaches `xor eax,eax; ret`.
- The byte at current is loaded after storing current+1. A nonnegative byte
  goes straight to the predicate. A high-bit lead takes the masked UTF-8
  assembly paths. The lead thresholds are `0xdf` and `0xf0`; continuation
  payloads are masked by `0x3f`, with shifts `6`, `12` and `18`. Each additional
  byte has a corresponding advance stored before its load.
- At `0x2786550`, ESI gets `(cp-0x5b) mod 2**32`. The unsigned comparison with
  `0xffffffe6` and `setb sil` identifies scalars outside `[0x41,0x5a]`.
  EDX similarly becomes `(cp-0x3a) mod 2**32`, and comparison with
  `0xfffffff6` identifies scalars outside `[0x30,0x39]`.
  AND of these predicates identifies characters outside both accepted ranges.
- The rejection branch at `0x278656c` reaches `mov al,1; ret`. Otherwise the
  advanced cursor becomes the next R8 and the equality/decoding loop repeats.
  The rejection path writes AL only: the remaining RAX bits retain the loaded
  end pointer. A canonical full-register boolean is not claimed.
- The `0x110000` comparison in the long decoding path returns false early for
  that decoded value. It cannot occur in valid UTF-8. Its presence does not
  turn this routine into a UTF-8 validator.

`scan_model` is independently authored Python expressing the accepted character
ranges directly. `interpret` instead applies the decoded instruction operands,
register widths, flags, branches and pointer stores to synthetic memory.
Recorded vectors compare the model with this static interpretation. Tests also
exercise ASCII exhaustively, Unicode width/range boundaries, nonzero cursors,
consumption of the first rejected scalar, and malformed-input counterexamples.
Neither mechanism executes the node or proves dynamic target equivalence.

## Caller census and first-party association

The generator scans every byte position of the entire authenticated `.text`
for both `e8` and `e9` signed-rel32 targets, without an alignment assumption.
The result is the direct call at `0x273b22a`, inside the actual FDE
`[0x273af20,0x273b4af)`. Its encoded target is independently decoded in the
caller slice. Setup at `0x273b215` forms current/end pointers in stack storage
and passes its address in RDI. At `0x273b22f` the caller tests AL; zero branches
to `0x273b2a6`. The nonzero path calls through slot `0x576dfd8`; if that
unbound helper returns a nonzero RAX, the following decoded branch falls
through to buffer stores at `0x273b247`. Those stores assemble **“asset name only accepts upper case characters and digits”** from
RIP-relative vector loads and an immediate qword. Those loads, stores and
literal bytes are decoded and rechecked; allocator semantics are excluded.

The same caller's `lea r8` at `0x273b429` refers to the Location at
`0x56e9b28`, whose `R_X86_64_RELATIVE` relocation points to the embedded
first-party path suffix `l1/src/dex_registry/perp_dex.rs`, line 30, column 33.
The record and complete path bytes are hashed; the captured build's absolute
prefix is omitted from the packet. This establishes first-party caller context,
not that the leaf was originally declared in that file. The allocation label
and descriptive function name are inferences; the instruction rule and error
message are observations.

This is an exhaustive **byte-pattern** direct-transfer census, not a whole
program xref graph. The hit agrees with the decoded local setup/call/result
sequence; the entire caller is not instruction-decoded or behavior-bound here.
Indirect calls, address-taken entries, prefixes, other sections and dynamically
constructed targets are outside the census. No unseen caller is invented.

## Novelty before packet creation

Checked at the repository baseline above, before adding this packet. With
`PR_LIST_DIR` set to the supplied directory containing the upstream title-list
copies, these exact searches all had exit status 1, empty stdout and empty
stderr:

```sh
rg -i '2786530' research/
rg -i '41444656' research/
rg -i '2786530' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
rg -i '41444656' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

The decimal form is the selected start address. No behavior-bound callee
requires an additional novelty search. The supplied title-list hashes are
retained in `records.json`; these are historical selection checks, not claims
about PRs opened after those snapshots. Repeating the research search after
adding this packet necessarily finds the new packet itself.

## Reproduction and validation

From the repository root, using Python 3.10+ standard library only:

```sh
python3 tools/asset_name_scan.py --out research/work-items/RE-001-asset-name-scan-94/
python3 -m unittest tests.test_asset_name_scan -v
python3 research/work-items/RE-001-asset-name-scan-94/verify.py
make verify
make catalogue-check
```

The checker fails closed on the pinned whole-file digest before analyzing
bytes. It verifies the complete leaf, FDE/CIE binding, padding, direct-caller
scan, caller slices, relocated Location, literal and model vectors. The
manifest has an exact whitelist including this packet, its tool and its tests;
extra, duplicate, missing and traversal entries are rejected. Regeneration
checks compare generated files byte for byte, including this README and the
human-readable instruction walk. No disassembler subprocess is used by the
tool, checker or tests. The implementation uses the existing stdlib ELF/FDE
parsers; the new restricted decoder is packet-specific, needed to validate
this previously unbound leaf under the no-disassembler-dependency constraint.

Analysis used Python 3.13.5. GNU objdump 2.44 was used only for initial local
inspection; no native-disassembler output is required to reproduce the packet.
No normalization mask is applied. No captured artifact was executed.

Baseline repository validation: `make doctor` reported static analysis ready.
`make verify` initially stopped on a node #115 LFS pointer. The requested
`git lfs pull` succeeded; all captured artifact digests and signatures then
passed, but verification stopped at the missing pinned reference
`references/can1357-hl/bin/hl-node-mainnet-new`. That unrelated checkout gap was
left unchanged. Final check outcomes are recorded in the uncommitted handoff.

## Non-claims, limitations, and next step

The rule requires valid UTF-8, readable pointer ranges, a current pointer at a
scalar boundary, and nonaliasing iterator/input storage. Malformed input can
be accepted after masked decoding, can reach the sentinel return, or can read
past the supplied range; there is no validity or continuation-length guard.
The static interpreter reports a missing-memory analysis error rather than
inventing a target panic. Pointer aliasing, asynchronous memory changes and
hardware faults are outside the model.

This packet does not recover the original Rust symbol, exact source type,
full asset-name policy, error enum, allocator/helper closure, entire caller,
node #115 behavior, runtime behavior equivalence, build provenance or binary
reconstruction. It adds no Rust component, coverage registration or progress
gate. Data/relocation evidence is limited to the selected caller context;
vtable, whole-ELF and other helper questions remain open.

Next bounded question: bind the caller's preceding input checks
and its error-tag contract to establish the full asset-name acceptance rule.
