# RE-001: node #94 `spot_meta.rs` Location and static-anchor inventory

This is a bounded static observation for assets, not a component completion gate.
Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The base repository commit is `1f8c67c63ca4794c9689235471c60297f8a5c985`;
the inferred, unlicensed reference is pinned at `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Only the exact embedded source-path bytes ending in `l1/src/spot_meta.rs` are
in scope. Embedded build-path bytes in the records come from the target, not the
analyst's environment. No local runtime state is captured.

## Reproduce and coordinates

Run from the repository root with Python 3.10+ stdlib; no disassembler,
network, installation, or target execution is required:

```sh
python3 tools/spot_meta_inventory.py --out research/work-items/spot-meta-inventory-94/
python3 -m unittest tests.test_spot_meta_inventory -v
python3 research/work-items/spot-meta-inventory-94/verify.py
```

`inventory.json` records ELF link-time virtual addresses and file offsets;
FDE ends are exclusive, and no runtime rebase is applied. `instructions.json`
contains the raw bytes and restricted decoder kinds for each complete selected
FDE, with offsets from its start. Input authentication precedes parsing or output.
The packet manifest hashes the outputs and documents; the inventory records the
producer and ELF/FDE helper digests. The decoder checks direct internal branch
alignment but does not establish CFG reachability. Unknown instruction forms
fail closed. Analysis is complete for the specified RELATIVE relocation census
and selected FDE ranges under these parser rules, not for all machine code.

## Method and observations

Scan `.rela.dyn` for relative relocations to the exact path in `.rodata`; decode
24-byte aligned Location slots in `.data.rel.ro` as pointer, path length, line,
column. The inventory retains relocation entries, raw data and exact path bytes.
Search executable sections for RIP-relative LEAs to each slot, assign each to an
actual `.eh_frame` FDE range, then fully decode each selected range from its FDE
start and reject candidates inside another instruction. A Location may occur
more than once at the same line and column; every slot is counted separately.
FDE extents are unwind ranges, not function boundary or component ownership proof.

For a finite list of byte probes, search the entire authenticated file for exact
occurrences. An anchor requires a decoded RIP-relative LEA to the exact bytes
inside a Location-referencing FDE and a directly adjacent pointer store and
matching qword length store, or a supported register pointer/length setup. The
record includes the setup bytes and every occurrence. A present probe without
such a proof remains unbound. Synthetic probes exercise absence;
they are controls, not claims that a feature or diagnostic is missing. The
numeric leads are searched as immediate MOVs; none satisfies the conservative
unique adjacent-field binding rule. Numbers alone do not prove units or roles.

Direct E8/E9 destinations are computed from signed displacements and recorded
only when they land at another selected FDE start. The selected FDEs are a
Location-xref slice, including broad inlined or shared contexts: these edges do
not establish exclusive spot metadata ownership, a complete call graph, or
reachability. Indirect calls and destinations outside the slice remain unresolved.

The unlicensed reference file is used only as a search lead. Reference literal leads at lines 864 and 875 are absent as exact byte sequences in this
artifact; another target literal has a different wording from the latter lead.
The leads at lines 865 and 868 occur in the target; the former remains unbound
under this packet's rule and the latter has a length-bearing anchor. These are
byte-presence observations, not validation of the reference implementation.
They can be checked without copying reference text by extracting the quoted
string on each indicated line and searching the authenticated artifact:

```sh
python3 - <<'PYCODE'
import mmap, re
from pathlib import Path
from tools.spot_meta_inventory import authenticate
lines = Path('references/can1357-hl/l1/spot_meta.rs').read_text().splitlines()
with open('artifacts/node/94/hl-node', 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
    authenticate(data)
    for line in (864, 865, 868, 875):
        match = re.search(r'"([^"\n]+)"', lines[line - 1])
        if match is None:
            raise ValueError('missing quoted reference lead')
        print(line, 'present' if data.find(match.group(1).encode()) >= 0 else 'absent')
PYCODE
```

## Evidence and limits

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 6 |
| counted_fragment_anchors | 0 |
| decoded_instructions | 139408 |
| diagnostics_absent | 2 |
| diagnostics_bound | 8 |
| diagnostics_probed | 12 |
| diagnostics_unresolved | 2 |
| location_leas | 599 |
| locations | 17 |
| out_of_scope_rel32_transfers | 5708 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 697011 |
| scoped_fdes | 333 |
| scoped_rel32_calls | 269 |
| scoped_rel32_jumps | 1 |
| unique_line_column | 6 |
<!-- END GENERATED METRICS -->

The manifest and `verify.py` pin the exact slot list, key counts, file whitelist,
full regeneration, and the report metrics. Tests exercise altered Location
fields, path and relocations, digest, ELF sections, FDE, shifted LEAs, instruction
lengths, literals and call bytes. See [RESULT.md](RESULT.md) for the verdict,
negative results, remaining gaps and next question. No Rust implementation,
compiler/build comparison, normalizations, or progress gate are claimed.
