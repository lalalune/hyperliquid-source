# RE-005: selected Gossip response variant0 vector and actual NodeIp elements

Target Linux x86-64 node #115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; serialization/RE-005 and
RE-012 gossip dependency. ELF virtual addresses, no masks/rebasing. New Rust
and research MIT, no unlicensed inferred reference source copied.

## Gap and recovered route

Existing field1-5/caller/state-construction packets establish primitive reads,
element fields and registration but provide no integrated Rust vector decoder.
Existing scalar response work leaves response variant0 unimplemented. This
change supplies its complete count/vector/element logical payload decoder,
starting after the outer variant was selected. It does not call selection a
complete whole response, infer networking units, or reread an outer tag.

The response call0x5aac901 reaches complete wrapper0x4de6210..0x4de6467,
which passes actual element0x5aaa460..0x5aaa628 to the complete vector helper
0x58251a0..0x58253e2. The element's invalid-tag diagnostic at0x93a9f1 is
exactly `NodeIp` (6bytes). Only rawindex0 is accepted in this selected native
copy. Its4-byte fixed field, boolean and field1-5 scalar are logical values;
calling the scalar a port, signed number or bounded-width integer is unproved.
The full outer response is retained context, not credited as fully decoded.

## Count, allocation and refund order

0x58251bc first reads a u64 count with the established reader (logicalcharge8).
For nonzero mode,0x58251d5 multiplies count by24 with overflow guard, adds the
prior charge with overflow guard, stores the new charge before comparing the
limit and refuses without decoding an element if exceeded. Canonical mode0/1
only is exposed; arbitrary raw modes have asymmetric treatment and are excluded.
Initial capacity is min(count,0xaaaa), stride24, with zero-count sentinel8.
Immediately before each element, a limited state checks charge>=24 then stores
charge-24. The real indirect call at0x58252cc gets that same updated state.
The refund failure helper/trap is a logical boundary, not a guessed panic ABI.

A successful element is copied as24bytes. At capacity the growth helper runs
before storing it. On an element error, active error fields are propagated and
the vector backing allocation is freed; prior scalar records have no observed
per-element destructor. The Rust implementation uses a real Vec of a24byte
repr(C) logical record, initial try_reserve_exact(min(count,0xaaaa)) and fallible
growth. This proves buildable ownership, not the original allocator/growth
algorithm. Resource refusal is explicitly safe-adapter Error::Allocation;
no such refusal is passed off as a reproduced native result or tested with a
fake allocator. Native allocation-failure/panic/unwind remains unclosed.

## Actual element and scalar-family composition

0x5aaa475 reads u32 tag; nonzero is invalid before further input. On zero,
remaining<4 fails without consuming fixed bytes or charging a boolean.
Otherwise0x5aaa52b/+52f commit cursor+4/remaining-4 BEFORE the following
charge1. Overflow or exceeded limit therefore retains those consumed4bytes;
charge overflow leaves the old count, exceeded limit retains the increment.
The marker is then consumed before flag>1 rejection. Missing marker is an
additional1 error after charge. Valid0/1 goes to actual0x5821340.

The field1-5 reader accepts nonminimal251/252/253 forms and charges8, with
fast threshold>8 and slow marker-first consumption. Its error constructor
field1 is5 on BOTH fast/slow routes, unlike the reused general Reader's2/3.
The native complete wrapper/slow0x5822710 are bound here. Reusing the MIT
Reader's equal value/cursor/charge relation and projecting only that active
error field avoids duplicating a valid parser or inventing dependencies.
Count reading uses general Reader unchanged; u32 parsing is credited unchanged
from the main Gossip request implementation. No new primitive byte credit.

Successful item nominalcharge is13 (tag4+boolean1+scalar8), independent of
encoded wire lengths; the fixed4-byte read itself has no separate charge.
After successful vector count n, limited total increment is8+13*n, but the
larger precharge24*n can refuse even if that final total would fit. Treating
this as a simple final-charge check loses real failure behavior.

## Evidence and qualification

Eleven complete FDEs total4395bytes/1183instructions: the response parent,
real wrapper/vector/element, u32/u64/field1-5 and slow/error helpers. These
are export denominators, including credited prior contexts, never new compiled
matching-byte or whole-component credit. records.json binds full bodies,
CIE/FDE/LSDA records, all call/branch rows, actual RELA writers, reader tables,
and exact diagnostic. GNU/LLVM/Capstone partitions agree and readelf confirms
full extents. Twenty actual instruction/data anchor corruptions reject below
the full-file identity gate; wrong/truncated captures separately reject.
No captured process or instruction evaluator was run.

Before the new Rust directory existed, oracle.py froze33545 expected rows,
SHA256b070dc9eea9c32025c297ffe3ee5e726d6830f115de89723c6dcf76d0bb666eb.
The oracle is explicit static scalar/budget/element mathematics, not production
Rust or captured-code execution. Both remain same-author fallible target
interpretation; no native execution oracle/peer-review claim is made. Corpus
covers every prefix of representative multi-element payloads, nonminimal count/
tag widths, invalid scalar markers/boolean/tag, countmultiply/add overflow,
precharge/refund boundaries, fixed-field-before-charge effects and suffixes.
No impractical huge vector is materialized by the oracle or probe; huge-count
fixtures fail on checked budget or first truncated actual element.

Actual Cargo debug/release each match33545 result/cursor/charged rows. Eight
actually compiled mutants terminate normally and differ: u32 charge, omitted
tag store, vector stride, refund amount, fixed endian, boolean domain, field5
error and dropped last element. Initial qualification rejected ambiguous source
selectors for tag-store and endian (two occurrences each). Selectors were
narrowed to the intended statements; production and frozen oracle never changed.
Original failures and successful actual/compiler outputs stay in ignored work.

```
source work/environment/new-three-env.sh
python3 -B research/work-items/RE-005-gossip-address-vector-115/verify.py
python3 -B research/work-items/RE-005-gossip-address-vector-115/qualify.py work/gossip-vector-replay
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-gossip-address-vector/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-gossip-address-vector/Cargo.toml -- -D warnings
make doctor verify catalogue-check reproduce
```

Host/Linuxrlib/fmt/clippy and repository results are in validation.json.
Unchanged583-file base qualification is reused explicitly (25skips), not a new
complete-suite result; hostedCI and Linuxexecution are not claimed. All92gates
and byte-comparison totals unchanged. Other response variants, original ABI/
inactivefields, allocator/unwind/formatting closure, arbitrary modes, units,
compiled-byte identity and integrated node behavior remain open. Next: compose
this route with independently qualified response siblings after they land.
