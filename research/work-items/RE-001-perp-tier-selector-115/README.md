# RE-001: node115 tier selection with actual split-ring CALL/RET

Assets / node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Addresses are ELF VAs.
The merged static `RE-001-node115-perp-tier-projection` packet (#2252) maps
the caller and leaves its lookup helper unclosed. This work qualifies ready
global, inline-tree and sorted-ring returned fields, including the real
283-byte search dependency and the caller's subsequent field projection.

See [the frozen contract](CONTRACT.md). Global keys below50 have priority;
otherwise the raw descriptor selects a tree or ring. Tree lookup is unsigned
and ordered. Ring lookup searches its two actual contiguous spans, returns
through the original CALL/RET, and the caller converts the logical position
to a physical72-byte row before projecting fields. No helper result is fed
into the instruction stream. Only initializer and diagnostic calls remain
explicit pre-call frontiers. No initializer continuation is composed.

```sh
python3 research/work-items/RE-001-perp-tier-selector-115/proof.py --objdump "$(command -v objdump)"
python3 -m unittest discover -s tests -p test_perp_tier_selector115.py -v
```

`proof.json` authenticates both complete FDE/CIE/GNU/Capstone contexts,
selected instructions, original direct/GOT calls and real source Location
`l1/src/perp_meta.rs:247:72`. All4,015 distinct tuples visit682 bytes/192
selected starts;2,264 rows execute the actual helper CALL/RET. The full
703B/197-instruction export is context, not raw machine-byte equivalence.
Twenty-four private actual-byte changes alter outputs and six more are
rejected. Original prefix observations are preserved in Git836753bd8 and an
owned external copy, rather than silently relabelled as closed evidence.

Pointer comparison retains exact object/cell/byte-offset identity; no semantic
pointer change is masked. Synthetic runtime guard, row fields and valid bounded
ordered containers are premises, not original global contents or full native
type validity. Inactive ring capacity is left unknown. Captured inputs, shared
tools, old packet and imports are preserved. New code/docs are independently
authored MIT; no unlicensed inferred source is inspected or copied. No captured
ELF process, Unicorn, live networking, signing or chain action is used.

Initialization/closure/vtable behavior, global construction, real original ABI,
caller reachability, metadata units, diagnostic/unwind and node integration
remain open. No component gate or byte registration is advanced. Next question:
close the initializer's actual callback/data and its ordinary completion before
composing the nonzero-guard path or claiming complete startup behavior.
