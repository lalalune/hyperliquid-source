# RE-012: the node #115 `info` literal and its single recorded RIP-relative reference

- Component ID: node-runtime (RE-012, APIs/gossip/startup)
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
- Claim status: **observation** of literal bytes and one cross-reference.
  CLI-token identity, dispatch semantics, call-path role, first-party ownership
  and novelty are **unresolved** and are not claimed here.
- Scope included: a bounded scan over twelve fixed candidate token strings in the
  `.rodata` section of the pinned file, a search for RELATIVE relocation and
  pointer slots holding any matched literal address, a scan for RIP-relative
  `.text` references to those addresses, and placement of each reference inside
  its `.eh_frame` FDE extent.
- Scope excluded: instruction semantics beyond the recorded bytes, branch/
  comparison structure, callers and callees, string-table roles, execution of
  the target, exhaustive xref census, source attribution and any reconstruction
  or completion claim.

## Reproduce

Read-only static check. The script reads `artifacts/node/115/hl-node` in place
and neither executes nor copies it. No network, no target execution, no
writes outside standard output.

```sh
python3 -B test-results/slop-workbench/check_cli_dispatch.py
```

Recorded result (check proof index 0, exit 0): the target digest was
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` both before
and after the analysis; `fde_count` = 135313; `tokens found: 1`;
`verdict: dispatch-candidate-fdes`. The verdict string is the scanner's own
label for "a literal was found and at least one reference to it was located";
it is not evidence of command dispatch.

Tooling: Python standard library only (pure-Python ELF section reader and
`.eh_frame`/CIE/FDE parser). Platform of the recorded run: the repository's
Linux validation workspace.

## Evidence

The scanner searched `.rodata` for NUL-terminated occurrences of twelve fixed
candidate strings (`hl-node`, `hl_node`, `run`, `abci`, `gossip`, `stream`,
`orderbook`, `info`, `visor`, `evm`, `metrics`, `chain`) and reported exactly one
match:

| Item | Recorded value |
| --- | --- |
| Literal | `info` (4 bytes, NUL-terminated, no printable byte immediately before) |
| Literal VA | `0x4312f2` |
| RELATIVE/pointer slots for that address | none reported (`relative_slots` empty) |
| Direct RIP-relative references | 1 (`direct_ref_counts` = `{"0x4312f2": 1}`) |
| Indirect references through slots | 0 (`indirect_refs` empty) |
| Reference instruction VA | `104680728` = `0x63d4d18` |
| Bytes at that VA (13-byte window) | `488d35d3c505fa4889dfc78424` |
| Containing FDE extent (half-open) | `104680382..104682536` = `0x63d4bbe..0x63d5428` (2154 bytes) |

Coordinates are ELF virtual addresses of the pinned file. The FDE extent comes
from the parsed `.eh_frame` record that covers the referencing instruction VA;
it is the extent of the containing FDE, not a complete-function claim derived
from the next unwind-index entry. The recorded 13 bytes start at the reference
VA and are not asserted to be a single complete instruction.

What the bytes show: the `.rodata` region of the pinned file contains the
NUL-terminated four-byte string `info` at `0x4312f2`, one instruction in
`.text` at `0x63d4d18` encodes a RIP-relative displacement that resolves to
that address, and the instruction lies inside FDE `0x63d4bbe..0x63d5428`.

What remains unresolved (not inferred from names):

- whether `info` is a CLI subcommand token, a service name, a log or protocol
  field, or an unrelated string; a literal match does not establish a role;
- what the containing FDE does, which branches or comparisons consume the
  loaded pointer, and whether any call path reaches a service entrypoint;
- whether the containing code is first-party node code or a dependency;
- whether this observation is novel relative to existing work items and open
  pull requests (the local claims index reports `indexComplete=false`, which is
  not a novelty finding).

## Implementation and comparison

Not yet implemented or measured. No Rust reconstruction, no source path
attribution, no compiler or build claim, and no byte comparison against a
rebuilt module exist for this window. Nothing here advances a component gate.

## Results and limitations

Metrics over an explicit denominator: 1 literal found out of the 12 fixed
candidate strings scanned; 1 direct reference found by RIP-relative pattern
matching; 135313 FDE extents parsed from the pinned `.eh_frame` with 0 parse
errors reported.

Limits:

- The literal set is a fixed, finite list of twelve candidate strings; the
  absence of the other eleven is a statement about that list only.
- The reference scan uses a fixed set of RIP-relative opcode prefixes and keeps
  at most two matches per target; it is not an exhaustive xref census, and
  references formed by other encodings (register-indirect loads, computed
  addresses, data tables not in the scanned sections) are out of scope.
- No RELATIVE relocation or pointer slot was reported for `0x4312f2`, so
  indirection through `.data.rel.ro` was observed as empty here and not proven
  impossible in general.
- The target binary was not executed and no behaviour is asserted; all results
  are static byte observations.
- No gate is requested. This packet documents an observation and keeps every
  incomplete component gate false.

Next question: determine from the pinned bytes what the FDE at
`0x63d4bbe..0x63d5428` does with the loaded pointer - specifically whether a
comparison against a command or configuration table consumes it - before any CLI
dispatch or ownership claim is made.
