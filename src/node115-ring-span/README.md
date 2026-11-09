# Node #115 ring-span leaf model

This independent Rust model follows the exact nine-qword output rule in `research/work-items/RE-001-node115-ring-span`, bound to target #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, leaf VA `0x2d55b30` (body `[0x2d55b30, 0x2d55bef)`, 191 bytes).

The model covers the full-word `2^63` sentinel arm, empty input, one-subtraction head reduction, strict wrap condition, 48-byte stride, duplicated endpoints and modulo-2^64 address arithmetic. `vectors.tsv` preserves the packet's 14 input/output cases. Tests also enumerate valid ring positions independently for capacities 1 through 16, all heads in `[0, 2*capacity)`, and counts through capacity.

This is a value-level leaf model, not recovered source typing or ABI. It makes no pointer dereferences and establishes no memory safety, allocation layout, concurrent behavior, caller ownership or whole-component equivalence. The packet states that the original leaf is call-free and has a complete decoded control-flow graph; no captured binary was executed or emulated here.
