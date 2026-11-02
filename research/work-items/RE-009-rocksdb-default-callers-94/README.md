# RE-009: three node94 callers pass disabled cache-override tags

- Component: storage; bounded static RE-009 follow-up.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`;
  reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No inferred reference Rust is copied or used as implementation evidence.
- Question: what cache-override tag do the three qualified direct edges pass
  into the two cache-pair entry functions?
- Status: ESI clearing, call targets and direct-CFG predecessors are observed;
  high-level `Option` labels and state/checkpoint names remain interpretations.
  This does not establish all possible callers, runtime reachability or a
  configuration-field identity. No gate change is requested.

## Reproduce

From the repository root, with the authenticated node94 artifact materialized:

```sh
python3.11 -B research/work-items/RE-009-rocksdb-default-callers-94/reproduce.py
```

Observed environment: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0.
The default installed decoder path is Apple's command-line-tools
`llvm-objdump`; use `--objdump` to provide another installed LLVM executable.
The producer authenticates the complete target and uses the previously
reviewed `tools/elf_index.py` and `tools/fde_extents.py` parsers; their current
SHA-256 identities are retained in `records.json`. It invokes only the
installed static decoder, reads local inputs and writes this packet.
No target instruction, network service or chain action is executed.

Each complete caller transcript begins with the exact decoder command:
`llvm-objdump -d --x86-asm-syntax=intel --start-address=<start>`
`--stop-address=<end> artifacts/node/94/hl-node`. There are no analysis
timeouts or reduced-profile databases. The complete owner ranges are decoded
from their FDE entries, with every instruction's bytes and contiguous coverage
checked against the target. Selected snippets are not used to resynchronize
the decoder at a convenient byte.

Expected and observed result:

```json
{"forwarding_anchors": 10, "owner_bytes": 8094, "owner_instructions": 1433, "qualified_calls": 3, "rejected_corruptions": 16}
```

## Evidence

Coordinates are linked ELF virtual addresses, with exclusive ends. FDE
records are independently decoded unwind extents, not proof of complete
source-level function boundaries or module ownership.

| Caller unwind range | FDE record VA | ESI clear | Direct call | Entry target |
| --- | --- | --- | --- | --- |
| `0x326e460..0x326e53b` | `0x115bce0` | `0x326e4a9` | `0x326e4ab` | `0x37d4e30` |
| `0x32fc190..0x32fc55d` | `0x1167128` | `0x32fc40d` | `0x32fc40f` | `0x37d4e30` |
| `0x47f1590..0x47f3086` | `0x1298df8` | `0x47f264d` | `0x47f264f` | `0x459a4c0` |

The complete transcripts are respectively `326e460.llvm.txt`,
`32fc190.llvm.txt` and `47f1590.llvm.txt`. Their raw owner hashes, bytes,
instruction counts, FDE metadata and call bytes are in `records.json`.
The caller counts are 56, 216 and 1,161 instructions over 219, 973 and
6,902 bytes. These are the retained three-owner analysis denominator, not
an equivalence or whole-node reconstruction percentage.

Every call has the same immediately preceding instruction, `31 f6`
(`xor esi,esi`). Writing ESI clears the upper 32 bits of RSI as well, so
the incoming first pair word at each target is exactly zero. The selected
seven-byte sequences are:

```text
0x326e4a9: 31f6 e880695600   xor esi,esi; call 0x37d4e30
0x32fc40d: 31f6 e81c8a4d00   xor esi,esi; call 0x37d4e30
0x47f264d: 31f6 e86c7edaff   xor esi,esi; call 0x459a4c0
```

The producer constructs a limited direct intra-owner CFG from the complete
LLVM decodes. All three call nodes are reachable in that model from the
owner entry, and each call's only modeled direct predecessor is its
immediately preceding ESI clear. There is no decoded indirect jump in these
three owners. This explicitly checks that a direct branch within the owner
does not bypass the clear and enter the call instruction itself. It assumes
normal return from preceding calls and does not reconstruct exceptional,
out-of-owner or computed entry edges; it is not a runtime path proof.

### Relation to the recovered cache pair path

[PR #1915](https://github.com/lalalune/hyperliquid-source/pull/1915) records
the downstream pair-forwarding path. That work left the entry RSI/RDX values
unknown. This packet adds their qualified call-site producers rather than
repeating a new reconstruction of those eight downstream ranges.

Ten target-byte anchors independently recheck the downstream junctions:

- Both entry functions save incoming RSI/RDX to consecutive stack words
  `+0x68/+0x70`, then capture the address of the first word.
- The state closure loads the captured words into RCX/R8 at
  `0x3be4b69..0x3be4b74`; the checkpoint loop does so at
  `0x4875cad..0x4875cb4`.
- Both tuned wrappers preserve RCX in R15 and R8 in R14.
- The selectors at `0x3421a56` and `0x42c71b1` test `r15b & 1`, load
  default 2 or 16 in EDI and use `cmovne rdi,r14` only for a set low bit.

All three qualified calls supply RSI=0 at the entry boundary. Composing that
observation with PR #1915's forwarding path additionally assumes the ordinary
ABI reading and preservation of the saved pair words across opaque
pre-collector helpers. Their transitive alias effects are not closed by either
packet. **Under those assumptions**, and if the selector is reached, the
first pair word still has its low bit clear, so selection retains **2 GiB for
the two state-entry edges and 16 GiB for the checkpoint-entry edge**. The
conditional result is therefore:

```text
RSI=0 at call + ordinary ABI + saved-word preservation + selector reached
    => state selector 2 GiB / checkpoint selector 16 GiB
```

Recovering the call-time RDX value is unnecessary for this conditional choice:
R14 is not selected when the preserved tag's low bit is clear. This does not
assert that RDX is zero or unused throughout the entire program, or that opaque
helpers cannot alter the saved tag through an unclosed alias.

The downstream function may fail, return early or never be reached in a real
run. The statement is about the selector count on these static call edges,
not an observed allocation or actual cache occupancy.

### Candidate inventory and its limits

The producer scans `e8`/`e9` relative-displacement byte candidates in all
file-backed executable sections for the two entry addresses. It finds the
three listed `e8` candidates, no `e9` candidate, and no
`R_X86_64_RELATIVE` addend naming either entry in `.rela.dyn`. Each of the
three `e8` candidates is separately qualified at an instruction boundary in
its complete FDE decode; the byte scan by itself proves no call semantics.

This inventory does not cover computed calls, arbitrary data pointers,
non-RELATIVE relocations or targets synthesized at runtime. Therefore it
does **not** establish that the program has no enabled cache override or no
configuration source for one. The claim remains these three qualified edges.

## Validation and controls

The digest gate precedes all parsing. Local controls then deliberately bypass
that gate and patch the read view used by the same operand validator:

- Three controls change the ESI-clear instruction's ModRM byte.
- Three controls change a direct call displacement.
- Ten controls change one byte in each downstream forwarding/selector anchor.

All 16 were rejected. The original target is never modified. These controls
establish that the retained evidence checks reject changed support bytes;
they do not execute mutations or prove source-level behavior. Full owner
byte hashes and complete contiguous LLVM validation additionally bind the
CFG's branch instructions to the authenticated target.

`validation.json` records exact repeatability of the generated transcripts
and records. No normalization masks, compiled implementation comparison,
target execution, Rust reconstruction or full component helper closure is
performed. Repository-wide checks are reported separately by integration.

## Result and remaining gap

Before this packet, the recovered forwarding path did not identify how its
entry words were supplied. Afterward, three qualified direct edges are known
to pass RSI=0. Default selection downstream follows only under the ordinary
ABI and saved-word-preservation assumptions stated above; opaque helper
alias effects remain unclosed.
No reference code is edited, no existing packet is changed and all component
gates remain false.

The program-wide override/configuration question remains open because the
candidate inventory is deliberately limited. Next question: identify the
dispatch and source ownership of the three caller owners, then determine
whether any computed edge can enter the two pair-entry functions with an
enabled low bit.
