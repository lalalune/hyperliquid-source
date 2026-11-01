# RE-001: node94 shell command routing and preparation requests

This closes the command-selection gap left by the shell retry packet (#159)
and consumers including checkpoint upload (#855) and startup log backups
(#1435). The node94 command consumer recognizes the exact bytes `2>&1` across
scalar and SIMD paths. A match keeps the original command object. Without a
match, either a leading `(` or trailing `)` selects an error request;
otherwise a Boolean option chooses one of two formatter templates. The
selected pair then feeds two ordered argument requests, `-c` and the selected
text, after a `/bin/sh` constructor request. Initial preparation can return
before any of this selection. This is new static research, not a reconstructed
Rust shell implementation or permission to execute any command.

- Task/component: **RE-001 / foundation**; bounded command selection and raw
  preparation/result protocol.
- Target: **node #94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference pin:
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred source was copied.
- Scope: four full unwind-described extents, original bytes, source-independent
  decoding, literals, relocations, incoming candidates and all explicit outgoing
  calls. Full callee closure, LSDA semantics, live effects, Rust build and
  component completion remain unclaimed; all gates remain unchanged.

## Retained evidence

| Role | ELF VA extent, end exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Command consumer | `0x13e4e40..0x13e58a8` | 2,664 | 550 |
| Candidate suffix checker | `0x13e9340..0x13e9430` | 240 | 65 |
| Request callback | `0x13e28a0..0x13e28b7` | 23 | 6 |
| Buffer callback | `0x13ee2a0..0x13ee2b4` | 20 | 5 |
| Total | Four complete extents | **2,947** | **626** |

GNU and LLVM exports agree byte-for-byte and on instruction boundaries; no
operand normalization or code masks are used. GNU readelf separately binds
all four FDE headers. `records.json` retains each extent's file offset, digest,
FDE/CIE/LSDA identity and every call/tail-jump record. Distant objdump C++
symbol annotations are preserved as tool output and are not function names.

Thirteen pinned RELATIVE slots resolve the formatter, preparation, allocation,
cleanup and request targets. In particular `0x576e8c8 -> 0x13e4e40`,
`0x576e878 -> 0x4ee91a0`, and `0x576e000 -> 0x1573450`. The latter is the
shared tail target of both callbacks: one dereferences its input once before
reading +8/+16; the other reads those fields directly. This establishes the
forwarded pair, without assuming the target's rendering contract.
`0x576e708` is independently bound through GLOB_DAT and dynsym to **close**.

The byte-candidate census finds no E8 calls to the primary entry, one RELATIVE
slot naming it, seven FF15 uses of that slot, and no FF25 use. Each candidate
is checked by complete Capstone decoding from its owning FDE start. The seven
call sites are `0x13c90ad`, `0x13c9255`, `0x144cbef`, `0x144d039`,
`0x14506d9`, `0x2017474`, and `0x37e3264`. This is a census of those encoded
forms, not all indirect callers or runtime reachability.

Ten data bindings preserve the suffix, two SIMD constants, five descriptors
and two shell literals. Selected descriptor bytes:

| Descriptor | Original bytes (hex) |
| --- | --- |
| Preparation path, `0x1f741d` | `0d7368656c6c5f72735f6f75742fc000` |
| Option=1, `0x200573` | `0128c01229203e202f6465762f6e756c6c20323e263100` |
| Option=0, `0x217750` | `0128c00429203e20c00c20323e263120262620726d20c8010000` |

[PROOF.md](PROOF.md) gives the instruction-address argument for full substring
recognition, candidate coverage, precedence, request order and raw result
handling. In particular, `2>&1` matches bypass the endpoint checks regardless
of parentheses; no match is inferred from the first/last-byte SIMD filter
alone. No exact formatted shell command is asserted from these descriptors.

## Reproduce and validate

From repository root, using materialized pinned inputs, GNU binutils,
LLVM objdump, Python 3.14.7 and Capstone 5.0.7:

```sh
packet=research/work-items/RE-001-shell-command-routing-94
python3 "$packet/export_disassembly.py"
python3 "$packet/verify.py" --controls
python3 "$packet/coverage.py"
python3 -m unittest tests.test_shell_command_routing -v
make doctor verify test catalogue-check reproduce
(cd "$packet" && shasum -a 256 -c MANIFEST.sha256)
```

The exporter runs only native disassemblers/readelf over the target as data.
It authenticates the capture before export, starts decoding at each owning
FDE, and checks complete byte coverage. The verifier authenticates one input
snapshot, binds 38 selected semantic instruction spans and the data/relocation
records, then checks regenerated JSON against the committed records.
Image/export plumbing is adapted from our MIT-authored packet in #1435;
this branch is independently based on main and does not depend on that PR.

**67 actual-byte corruption controls** bypass whole-image hashes, body hashes
and export checks, so these guards cannot mask failures in the semantic
bindings: 38 instruction spans, 13 relocation addends, 10 literals/descriptors,
four FDE extents and two dynamic-import fields. A separate prologue mutation
outside the semantic spans checks the full-image, body and independent-export
guards individually. No captured bytes are changed on disk or executed.

The interval checks cover 4,097 lengths and 8,378,371 distinct candidate
positions; all 65,535 nonzero 16-bit masks satisfy the candidate-removal
identity. These are combinatorial checks of the written proof, not runtime
fixtures or target equivalence. The four focused tests cover authentic
regeneration, the 67 controls, independent integrity guards and interval/mask
checks. Exact repository-wide results are recorded in `validation.json`.

Local native tools: GNU objdump/readelf 2.47.20260726 and LLVM objdump 18.1.4
on macOS arm64. The first baseline doctor invocation selected Apple's objdump
and failed its GNU-tool prerequisite. A process-local PATH selecting the
already-installed GNU tools corrected this; the failed invocation is retained
in the validation record. No tool installation or global configuration change.
No captured node/visor, emulator, shell request, live endpoint, key, chain
action or paid dataset was used.

## Overlap, limits and next step

`overlap.json` records the all-state PR audit and inspected open/related-closed
patches. #159/#855 and #1435 bind callers but leave this consumer's body open.
#634/#658/#725 cover the distinct collection helper at `0x1455c00`; #424 names
the request callback without recovering its body. #1330 covers the general
formatter request controller. Visor shell packets use a different artifact
and do not establish these node94 addresses or the full-length search rule.

Observations are the byte/data/layout/call/result bindings. The bounded
inference is the selection relation under the valid-buffer, Boolean-option
and normal-helper assumptions in PROOF.md. Unknowns include preparation path
contents and directory effects, complete formatter output/escaping, constructor
and argument-helper ABI, allocation/panic paths, transitive spawn/wait behavior,
error object types, cleanup/unwind ownership and runtime equivalence. No Rust
implementation, build identity, whole-function behavioral equivalence or gate
completion is claimed. Next recover the preparation helpers and process
argument construction before asserting an exact argv or shell side effect.

New code and text are independently authored under MIT; original binary
excerpts retain their original rights.
