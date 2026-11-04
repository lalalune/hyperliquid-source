# Node #115 reverse engineering

Start with a bounded #115 question and the [scope](SCOPE.md). Then run:

```sh
make doctor verify catalogue-check
make index fde-index
python3 tools/rea.py target 115
python3 tools/ghidra_plan.py --release 115
```

The index lists unwind starts, not complete functions. FDE ranges, control flow,
called helpers, data, relocations and error behavior must be checked for every
claim. Comment names and diagnostic paths alone are not verified ownership.

Use the connected REA server for focused static analysis. Keep Ghidra projects
and transient output under ignored `work/`. Preserve complete evidence records,
provider versions, options, original addresses and the full artifact digest.
Store reusable results under `research/work-items/<task-id>/` using the template.

Running the captured executable, using live networks or submitting chain actions
requires separate authorization. Independent Rust tests and static parsing do
not establish native node execution or whole-node equivalence.

The active tree contains only #115 implementations, their needed shared analysis
helpers, and licensed dependencies. Historical source is available in Git;
reusing it requires a new, target-specific validation record.

`make fde-gaps` classifies the authenticated #115 gaps between unwind ranges
and checks direct branches, RIP-relative operands and relocation references.
See [the bounded gap evidence](../research/work-items/RE-001-fde-gap-classes/README.md).
The resulting islands are candidate code or data, not validated functions.
