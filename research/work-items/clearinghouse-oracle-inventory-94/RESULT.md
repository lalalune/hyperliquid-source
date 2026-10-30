# Result — RE-007 oracle slice, node #94

This is an **incomplete, bounded static inventory**, useful for two diagnostic
anchors and one call edge; it is not recovery of an oracle path or the RE-007
gate. Input: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses below are ELF virtual addresses, and ranges are half-open.

## Observations

The restricted RELATIVE-relocated first-party Location census yields **21**
records, all `oracle.rs`, **72** RIP-LEA sites and **67** distinct containing
FDE ranges. The JSON lists every Location slot, filename pointer, line, column,
instruction bytes, site and range. A Location may appear in many compiled
contexts: FDE containment does not make its owner an oracle function. GNU
objdump 2.44, decoding each containing range from its FDE start, confirmed all
72 sites as instruction-start LEAs. The FDE table has 121,299 entries; it is
not a denominator of all functions.

Within FDE `0x3261290..0x326151a`, Location `0x56df7b0` is used at
`0x3261346` and identifies `l1/src/clearinghouse/oracle/oracle.rs:627:35`.
Two direct LEAs in that range bind these adjacent, non-NUL-terminated strings:

| Diagnostic | Literal VA | length instruction | LEA instruction |
| --- | --- | --- | --- |
| Missing reference oracle | `0x584655` | `0x326149d`: `b8 18 00 00 00` (24) | `0x32614a2`: `48 8d 15 ac 31 32 fd` |
| Price moved too far from reference oracle | `0x58466d` | `0x3261322`: `b8 29 00 00 00` (41) | `0x3261327`: `48 8d 15 3f 33 32 fd` |

Both paths converge at `0x326132e` and store the pointer and length at stack
slots `0x10` and `0x18`. This supports the text/length pair and co-location,
not the semantics of every branch, a recovered function name, or a validated
threshold. `Unexpected length of prices to set in oracle` and `Price too far
from oracle` occur in `.rodata` but lack a validated length-bearing LEA in a
Location-scoped FDE. The former is part of a longer encoded template (a LEA
at `0x3803190` targets one byte before the substring); the latter has a LEA
at `0x3a00c37`. Neither is promoted to a scoped claim. The two additional
positive/update-frequency phrases also occur outside this scope; three named
updater/finite/decimals candidates have no exact `.rodata` occurrence. The
JSON records all nine candidates, including zero-occurrence negatives.

The direct call `0x26f7929: e8 92 44 ff ff` in FDE
`0x26f7280..0x26f7ee8` lands at FDE start `0x26ebdc0` (ending `0x26eff10`).
Both ranges contain LEAs to Location `0x56bd1a8` (`oracle.rs:197:18`), at
`0x26f7be6` and `0x26efa7a` respectively. Their semantics and reachability
under any particular input remain unknown. This is one static edge, not helper
closure or a mark-versus-oracle classification.

In the diagnostic FDE, `0x32613bd` multiplies by immediate `0x2710` (10000),
while `0x32613e2..0x3261418` checks a byte against 7, subtracts it from 6,
and uses the result to index a double table beginning `0x584b08` (1, 10,
100, 1000, 10000, 100000, 1000000) as a divisor. The numerator is converted
from an integer-like input. This shows a decimal scaling operation in this
context; it does **not** establish the source names, a global asset limit,
price unit, scale convention, sign convention, or raw/display field identity.
All eight requested named constants remain unresolved; incidental immediates
are not semantic bindings. Staleness, price-distance ratios, leverage and price
kind are not established here.

## Scope and non-claims

The census includes all matching Location uses, including shared/inlined uses
in ranges also relevant to the separate margin investigation, because omitting
them would falsify the census. It does not inspect or claim `margin_table`
Locations, margin formulas, the liquidation admission path, or any ADL debit
path. The unlicensed can1357 tree is a lead, not source or implementation;
its historical imported literal classification is not used as proof. The
reference checkout is absent locally (pinned commit
`999556f6e0a474b8312db96ec3149e1c44e97c23`), so no reference source was read.
No captured executable was run. No behavior test, Rust implementation, raw or
normalized body comparison, data/relocation/vtable/helper closure, node #115
comparison, full-ELF equivalence, or reviewed completion gate is claimed.
Next, trace the length-bearing diagnostic FDE's inputs and indirect calls with
validated CFG and data xrefs to determine price units and threshold provenance.

## Command outcomes (contribution tree)

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985` with pinned LFS inputs.

- `python3 tools/clearinghouse_oracle_inventory.py --out research/work-items/clearinghouse-oracle-inventory-94/`: exit 0
- `python3 -m unittest tests.test_clearinghouse_oracle_inventory -v`: 24 tests, OK
- `python3 research/work-items/clearinghouse-oracle-inventory-94/verify.py`: PASS
- `make verify`: exit 0
- `make test`: exit 0
- `make catalogue-check`: exit 0

