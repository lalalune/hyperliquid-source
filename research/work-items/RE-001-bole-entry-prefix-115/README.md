# RE-001: qualify node115 private free-entry selection before lookup

Exchange / node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Original coordinates are ELF
VAs. The static `RE-001-node115-bole-entry-counter-order` packet credits the
whole parent body973B/189 instructions and documents field origins. This
work addresses the remaining independently authored Rust prefix and actual
ordered selection/state qualification, not another address mapping.

Read [the frozen contract](CONTRACT.md). A zero primary index returns raw2;
otherwise primary and secondary bounds precede the first-free scan. List
order and arbitrary nonzero occupied words matter. Only after selection does
the raw header choose one of two actual lookup calls or the raw2 return.
A bound failure cannot be replaced with a later free entry. The auxiliary
word and floating bits remain live for the unimplemented continuation.

`native.py` interprets actual entry instructions and real raw2 RETs. Every
lookup and diagnostic stops before its original CALL, with no supplied helper
result. These frontiers are owned analysis labels, not original Rust enums.
`proof.py` authenticates target digest, full FDE/CIE/GNU/Capstone context,
selected instruction boundaries, direct targets and diagnostic RELATIVE slots,
then freezes outputs and private actual-byte COW controls before Rust.

```sh
python3 research/work-items/RE-001-bole-entry-prefix-115/proof.py --objdump "$(command -v objdump)"
python3 -m unittest discover -s tests -p test_bole_entry_prefix115.py -v
```

Domain: bounded disjoint objects, primary<=16, list<=32, secondary<=16.
Map header words are raw premises with no original-validity or reachable-caller
claim. Inactive output/stack bytes and pointer coordinates are not logical
payload. MOVSD copies bits; no floating arithmetic is interpreted. Incoming
objects, including the later+38 counter, remain unchanged. Nothing after
lookup is composed. The Bole name is a diagnostic association, not a recovered
public operation or proof of balances, prices or state transitions.

New code/docs are independently authored under root MIT; shared helpers and
old evidence are credited and preserved. No unlicensed source, captured ELF
execution, Unicorn, live networking, chain action or signing is used. Full
function/source-byte identity, unwinding, lookup internals, numeric rounding,
opaque operation effects and whole-component completion remain open. No
gate or byte registration is advanced. Next question: close the selected
lookup representation and its failure/state behavior before composing the
later saturating count and numeric operation.
