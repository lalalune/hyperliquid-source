# Validation scope

- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Baseline `make doctor verify catalogue-check reproduce`: exit 0.
- Full `make test`: 76 isolated files, 380 reported cases, three optional skip
  records, zero failed files, exit 0. This run uses the unchanged tracked core
  sources fingerprinted in `validation.json`; new packet/library are qualified
  separately. No hosted CI or independent peer review result is claimed.
- New Rust: rustc1.95.0 opt0, opt3 and repeated opt3 each match 226,976 rows;
  optimized library digests repeat. Nine compiled semantic controls return
  normally and produce mismatches. Cargo offline/locked tests: two pass.
- Target checks: both full artifact/owner identities, native partitions, FDEs,
  fields, unique selected relocations, source/data and computed-edge records
  reproduce. Five operand counterfactuals, six structural controls, one duplicate
  parsed-provider record and one truncated-capture control are observed.
- Source/driver rustfmt checks pass. Supplemental PT_LOAD mapping and actual
  transform diagnostic relation pass; no retired input is required.
- Final catalogue-check and inventory reproduction pass after staging the new
  packet/library. Five existing catalogue controls pass. Generated README/SVG
  inventory changes only from 7/3/28 to 8/4/29 (Rust areas/manifests/work items);
  dependency byte comparisons and all component acceptance gates are unchanged.

The complete locally retained raw logs and comparison outputs are under ignored
`work/environment/node115-task/`. Their digests and replay commands bind these
observations. Skipped prerequisites, full-reader behavior and whole-node
acceptance remain unqualified; all 92 full-scope gates remain false.
