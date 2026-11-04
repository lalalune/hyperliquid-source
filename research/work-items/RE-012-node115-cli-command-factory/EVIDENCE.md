# RE-012: bind the Node115 CLI declaration producer to owned validators

- Component ID: node-runtime
- Target: Linux x86-64 Node115, 105896032 bytes, SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
- Reference: PR2034 immutable d675d68d872ed8402c21845b610ca2abd619e4bf, CONTRACT.md; known consumers/layouts credited, factory explicitly excluded there.
- Claim status: raw-byte/FDE/RELA observations; source-level names/command association are bounded inferences; parser/default/grammar/transitive helper behavior unresolved.
- Scope: complete 25353-byte factory, five local owned callback bodies and five once adapters. Four context helpers are separately credited; common-options helper/parser/output constructor are excluded.

## Reproduce

See README.md for exact root-cwd commands and native options. The public collector authenticates the complete target first. Tool versions/options and original native stdout hashes are in native-comparison.json. No captured execution/emulation, external model/provider, network service, key, chain or signing effect.

## Evidence

records.json re-derives 14 exact-length command constructions, 24 local argument registrations, 20 validator bindings/60 actual method RELA writers, FDE bodies and bounded LSDA call sites. spec.json retains original VA/store/data witnesses. Native files retain all 15 complete ranges, 29976 bytes/4584 instruction rows: 27208 primary bytes and 2768 separately credited context bytes. GNU/Capstone addresses and bytes agree; no normalization masks. No function/module coverage or Rust implementation credit follows from these counts.

## Implementation and comparison

Before: current main has no factory producer packet/collector; PR2034 leaves the factory opaque. After: standard-library collector, closed inventory verifier and actual-target corruption controls reproduce the declared producer records. Independently authored Rust, Cargo/compiler closure and source-to-target executable comparison are not yet implemented/measured. No binary transplant or stub implementation.

## Results and limitations

Focused actual-target controls and native replay are distinct from required repository checks. Exact final head and actual mandatory command outcomes must be reported in the PR; pending/failed checks are not success. The first FF15 prefix control failure is retained with its source correction; no assertion was removed. Source-authoring Job e80ab08d exited0 but was classified failed-leftover-child by the supervisor; cleanup confirmed0 and its lock released. It was not rerun or represented as a validation pass.

All component gates stay false, 0/92 unchanged; no byte window added. Field type identities, arbitrary aliasing, full parser/default/help behavior, common options, address/IP grammar, opaque formatting/allocation/drop helpers, action chains and integrated node behavior remain unknown. Next: connect this producer to actual parser consumption/default behavior, retaining the known separate output constructor boundary.
