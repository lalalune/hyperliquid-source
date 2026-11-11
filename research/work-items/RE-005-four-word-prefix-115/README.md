# RE-005: full node115 private four-word prefix decoder

Serialization / node #115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. New work answers the
bounded return-value and partial Reader-state question for the complete
private body `0x2ce1730..0x2ce198a`; addresses are ELF VAs, not rebased PCs.
The existing block-fill-writers packet established the fourth value's store,
but did not implement this decoder or compare its full helper graph.

See the pre-Rust [contract](CONTRACT.md). The private operation performs four
separate scalar reads, consumes a mode byte, then optionally reads a fifth
scalar. A limit8 counterexample consumes one byte and retains charge16;
using the existing aggregate `read_four` would instead precharge32 and
consume none. The mode byte has its own charge and is consumed before invalid
mode or fifth-value errors. This is a prefix, not a whole-message schema.

`native.py` interprets the actual full private entry and real scalar/slow/error
CALL/RET graph; no helper results are mocked. `proof.py` authenticates the
target, complete FDE/CIE records, raw GNU/Capstone instruction pairs, signed
dispatch data and RELATIVE helper slots. Private COW mutations alter actual
instruction bytes and must change a logical output with the same initial
state. Captured input remains read-only. No original executable, Unicorn,
live networking, chain actions or signing are used.

The comparison projects only active logical result fields, consumed input and
charged count. Unknown inactive storage stays unknown, including the optional
word for mode0. Failure's fourth-slot caller canary must survive. Canonical
mode0/1, little endian and disjoint valid storage are premises. Raw arbitrary
Reader modes, original enums/ABI, message field meanings, unwinding, complete
protocol validity and integrated node behavior remain unclaimed. All92 gates
and byte-window registrations remain unchanged.

The unchanged project-authored MIT `node115-u64-reader-state` is the genuine
source dependency, credited rather than duplicated as new primitive work.
Its aggregate API is deliberately not used. No unlicensed inferred source
was inspected or copied. Static field-origin work is credited to
`RE-005-node115-block-fill-writers`; neither that packet nor captured inputs
are changed. New code/docs retain the repository MIT license.

Reproduce from the repository root after activating the documented Python /
Capstone / GNU binutils environment:

```sh
python3 research/work-items/RE-005-four-word-prefix-115/proof.py --objdump "$(command -v objdump)"
python3 -m unittest discover -s tests -p test_four_word_prefix115.py -v
python3 research/work-items/RE-005-four-word-prefix-115/verify-rust.py --rustc /path/to/rustc --out /fresh/owned/output
```

The pre-Rust Git seal is `eb1274be65964c8c7d2642505b50df40db445877`.
All4,293 frozen rows are distinct `(input, limit, initial_charge)` tuples.
Four whole FDEs export1,161 bytes/319 instructions; the corpus visits
1,128 bytes/309 instructions: private150/150 (602B), scalar69/69 (229B),
slow85/95 (283/316B), constructor5/5 (14B). The unvisited33B are the
slow reader's u64-success block: it requires remaining>=9 while this actual
scalar caller selects slow only when remaining<=8. Those instructions are
exported, not credited as visited. Eleven genuine byte COW changes alter
outputs; captures rehash unchanged. See `proof.json`, `native-controls.json`
and `execution-recipe.json` for hashes, bindings and retained initial failures.

Outputs are static-contract qualification, not captured native execution or
whole-program equivalence. Tool versions, exact build commands, comparison
counts, retained failures and scope qualifications accompany final receipts.
Next question: which original schema owns the four fields and how does its
caller validate the returned prefix and remaining input?

Final results: clean opt0/3 and same-path repeat match all4,293 rows;128 client cases pass;11 compiled mutants all differ and fail the fixture. Seven focused tests, format/Clippy, doctor, verify, catalogue generation/check and actual reproduce pass. See [qualification](VALIDATION.md) for exact commands, the retained initial sample failure, shared catalogue overlay and pending own full-CI limit. No gate is advanced.
