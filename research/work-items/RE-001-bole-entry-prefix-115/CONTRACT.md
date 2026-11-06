# Pre-Rust: private Bole-associated free-entry prefix

RE-001 / exchange. Node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. All coordinates are ELF VAs.
Parent FDE `0x2c80670..0x2c80a3d` is973B; only `native.SPANS` is selected.
The existing entry-counter-order packet establishes static observations;
this work qualifies the prefix's actual ordered selection and live lookup
continuation state. It does not implement the whole operation.

The native entry reads an incoming primary index. Zero returns raw qword2,
before reading the context. A nonzero index is compared unsigned with the
primary length. The >= arm stops at the actual diagnostic call2c80a27.
An admitted index selects a344-byte row, with an index-list pointer at+58
and length at+60. The object secondary pointer and length are+98/+a0.
Each list index is checked unsigned against secondary length before selecting
a32-byte row. Its+8 u64 is inspected. Nonzero skips; zero selects the first
such row. A failed secondary bound stops before2c80a37, even if a later list
entry would be free. Exhausting the list returns raw2. Duplicate indices,
occupied raw words other than1 and index order must remain distinct.

After selection, actual frame stores preserve incoming auxiliary word,
primary index and floating-input bits, plus the selected secondary index in
R14. A header word at object+6c8 is negated; only raw0x8000000000000000
sets overflow. All other words take lookup B at2c80780 ->4556410.
The overflow arm tests the word at+6d0: zero returns raw2; nonzero prepares
lookup A at2c8074b ->35bf460. Both are stopped BEFORE the actual CALL.
No normal helper return, lookup success, selected value, later saturating
counter increment, floating calculation, opaque operation or resulting
large output is supplied or composed. Only raw2 paths execute a real RET.

A/B are analysis labels for live frontiers, not native return enums. Their
projection is primary index, selected secondary index, incoming auxiliary
word and preserved floating bits. P/S label pre-diagnostic guards and their
compared index/length; no diagnostic behavior is assigned. Original source
types, names, field meanings and valid header domains remain unknown.

Premises: valid disjoint nonwrapping bounded memory; primary length<=16,
list length<=32, secondary length<=16. The supplied list belongs to the
selected primary row when admitted. Raw header words are entry premises;
their original container validity and actual caller reachability are not
claimed. No map storage is dereferenced or assumed. Floating bits are copied
by real MOVSD loads/stores only, without arithmetic or rounding assumptions.
All incoming objects, including the later counter+38, must remain unchanged.
Stack/frame identities are checked; unknown inactive bytes stay unknown.

New Rust will expose a safe logical selection frontier over these arrays;
out-of-domain lengths are a separate own refusal, not a native error claim.
The implementation is independently authored MIT; no inferred unlicensed
source is copied. Native expectations, contract and output-changing byte
controls must be Git-sealed before Rust authorship. All92 gates remain false.
