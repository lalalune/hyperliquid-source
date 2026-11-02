# RE-005: fixed32 and two-map admission, output and cleanup

Caller1f646e0 reads fixed32, then map28916c0, then map2890ea0. The unresolved
question is their composition: shared counter admission, distinct field order,
active output and cleanup after a later error. Fixed/scalar primitives, paired
values and single-map semantics are credited context, including peer1535 and
author1742/1779. This is not a new standalone claim for those clones.

For mode QWORD1, limit1000 and incoming helper counter C in[0,1000], original
first/second counts M,N must satisfy BOTH C+40+96M<=1000 and
C+48+85M+96N<=1000. Count decoding charges8; fixed32 charges32; each admitted
original entry refunds96 then charges20/32/32/1, for net85logical units after
reservation refund. Duplicates remain original attempts. Distinct key counts
and final counter alone do not predict reservation admission.

Consequently M+N<=11, with equality only(C,M,N)=(0,10,1). For C>0 the sum is
at most10. A fresh-helper C0 example may consume1073wire bytes with final
counter983. This does NOT say the surrounding greeting invokes this helper
with C0 or admits that complete message. Every first map has at most10attempts,
every second at most9; all reached insertions remain in one nonfull leaf.

Success writes outer QWORD0, fixed32 at+8, first root/height/length at+40/+48/+56,
second at+64/+72/+80. Maps have separate key spaces and sorted last-value
associations. Empty maps define root0/length0; copied empty-height bytes remain
inactive and excluded. Symbolic fresh owned identities represent allocations;
no runtime pointer, source nominal type or native ABI is invented.

Failure forwards outer QWORD1, kind at+8, needed at+16 for kind0, expected/found
at+9/+10 for kind3; kind2 has no active payload. It retains reached input and
counter stores. First failure skips later calls. Second-map body failure drops
its own partial leaf before returning; caller then drops the completed first
descriptor. Thus actual releases occur second then first when both allocated.
A count/reservation failure does not invoke that map's body drop. Empty drop
calls do not free a leaf. Success transfers both maps and releases neither.

Each allocated map requests one1024-byte alignment8 leaf. Nonfull insertion
uses20byte key and72byte value movement strides while values have65 active
bytes. The shared split/ancestor/unwind/terminal bodies are retained as static
identity context but not claimed semantically. Ordinary preserving returns,
valid disjoint stable Reader/input/output/stack/heap and exact helper request
semantics are premises. Allocation failure, faults, aliases, races and unwind
behavior are excluded.

Base e5c9b6436876b2a4a39daef813171f9879317699; node94 Linux x86-64 ELF,
91774280bytes, SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Identity includes16complete FDEs/14953bytes/3277GNU rows,26initialRELA,
27direct transfers and28data extents953bytes. Raw GNU2.42/LLVM18.1.3 exports,
complete FDE/CIE and actual helper/data/initial relocation records are retained.
No masks or omitted rows. File addends do not establish loaded pointers or
callee implementations. These counts include credited dependencies, not new
recovered byte credit, semantic coverage or whole-module completion.

PROOF.md is the unchanged manual pre-checker snapshot. Its remaining-work
section and no-checker wording describe that earlier point, not the final
packet state. FREEZE-CHECKPOINT.json records both normal/-O authorities before
checker creation. Supplied values and selected field widths constructed25905
distinct mathematical inputs: all1001incoming counters, joint admission/store
boundaries, two-map duplicate and insertion histories, cross-position unsigned
keys, word/byte/fixed32 preservation, selected complete wire truncations,
nonminimal counts, suffixes, malformed count/value markers and ordered cleanup.
The checker separately parses bytes and maintains logical leaves;29wrong
accounting/layout/input/ownership rules must disagree. These expectations are
constructive mathematics, never captured native outputs or native equivalence.

A post-checker manual coverage review found that the initial giant counts used
C0 and did not separately witness reservation addition overflow. ADDITION-FROZEN.json
and its original source transparently add42boundary inputs AFTER the main
checker existed. They are not part of the25905pre-checker claim. Twelve cases
isolate addition overflow with a non-overflowing product: the old counter is
retained without a reservation store. Neighboring cases cover the stored-then-
limit failure and count-charge precedence. No initial expected result or main
checker relation changed. Normal/-O replay and checks of this supplement are
separately recorded. Replay via regenerate_addition.py and check_addition.py.


Before selection,472open PR bodies in a complete non-atomic five-page inventory
had no focused address match. Current-base research/docs also had no focused
hit. Recheck before submission. Canonical varint/slow-width/stream schema,
peer1365, fixed20/fixed32/peer1535 and author1723/1742/1779 remain credited;
generic MIT static evidence tools are self-contained derivatives of author1779
and its credited predecessors. No unlicensed inferred source is copied.

VALIDATION.json records only observed checks and their limits. Full make test
is NOT RUN because flat discovery includes captured-instruction evaluators
outside static authorization. No captured execution, instruction interpreter,
symbolic CPU, compiler/Rust build, hosted CI, arbitrary modes/limits, allocator
implementation, whole greeting/connection, recovered ABI or component gate is
claimed. Global registries, pins and acceptance gates remain unchanged.
New code/docs are MIT; artifact excerpts retain their original terms.

Reproduce with an authenticated non-executable node94 and fresh outputs:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimized Python and compare exact receipts; run root doctor, verify,
catalogue-check and reproduce. Passing integrity/identity controls alone does
not establish the conditional semantic relation or satisfy a full component gate.
