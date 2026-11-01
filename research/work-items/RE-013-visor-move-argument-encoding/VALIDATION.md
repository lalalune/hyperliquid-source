# Static validation and limits

`validation.json` records the normal verifier's 169 rejecting controls and two fresh, identical evidence trees. `validation-optimized.json` records the same controls with Python `-O` and no duplicate tree regeneration. All checks use explicit exceptions rather than Python assertions. Both receipts retain source hashes and identical mathematical certificate results. Neither run executes/emulates the captured program, a shell command constructed by it, or a target-instruction evaluator.

`collect.py` first checks the entire 8,305,392-byte input SHA-256 and refuses an existing output directory. It resolves unique file-backed PT_LOAD ranges, checks 92 selected instruction bindings, five data records, 14 RELA bindings and the `memcpy` dynamic symbol, and parses actual FDE ends plus their referenced raw CIE records. A private immutable snapshot is independently disassembled by GNU and LLVM. Every instruction byte is compared to mapped artifact bytes; both complete partitions agree. The only permitted partition adaptation is joining a standalone LOCK prefix, if present. Local direct branch destinations must be instruction boundaries. Full exports include diagnostics and landing pads; selected context is separately labeled. No function identity is inferred from printed nearest-symbol labels.

The records include parser/tool identities and deterministic export hashes, not repeated pretty-printed instruction arrays. GNU output remains readable; LLVM output uses deterministic gzip. The metadata preserves complete raw FDE/CIE records, but does not prove LSDA semantics, an unwinder, compiler identity or runtime ABI. The exact six extents are based on FDE start/end plus the `.eh_frame_hdr` entry, not merely adjacent unwind starts.

Controls are deliberately separated by their actual strength:

| Kind | Count | What is tested |
| --- | ---: | --- |
| Instruction/data binding | 97 | Each of 92 instruction operands and five data records is changed at its PT_LOAD-translated file coordinate, and `contract()` is called **without** the whole-image hash gate. |
| RELA/import binding | 43 | Each selected RELA kind/symbol/addend is changed independently (42); one dynamic-name mutation changes `memcpy`. These also bypass whole-image identity. |
| Raw metadata | 12 | One byte in each retained FDE and referenced CIE is changed and extent/raw-record validation rerun below identity. Shared CIEs are explicitly retained per owner; these are integrity checks, not 12 independent unwind proofs. |
| Native/cache consistency | 3 | A row is removed, an exported byte is changed, and a retained row count is changed. |
| Value-level counterexamples | 7 | Five quote masks and the U+2000 table bit are perturbed; mathematical set/equation checks reject them. The declarative grammar rejects NUL outside its domain. |
| Whole-image/output gate | 2 | A changed target is rejected before creating output; an existing output destination is refused. These two are **not** below-hash semantic tests. |
| Fresh native mutation binding | 5 | Changed mode, original-pointer operand, NUL comparison, raw mask and separator store are independently re-decoded by both native tools; the altered instruction bytes are retained in the receipt and the operand contract rejects them. This is not mutant execution or proof of the mutant's behavior. |

The two regenerated trees each contain all 20 observed files and compare byte-for-byte, including transfers and metadata. Optimized Python repeats all negative controls, fresh native mutant decoding and algebra, while skipping only the two expensive full-tree regenerations. `MANIFEST.json` hashes retained packet files; it is an integrity index, not external corroboration.

`algebra.py` contains byte-set equations and a declarative longest-prefix chunk grammar. It has no instruction parser, program counter, registers, flags, simulated memory, callbacks, process execution, or shell parser. Scalar equations enumerate canonical UTF-8 encodings using Python's codec as an independent value source and compare the captured table predicate to the explicit 25-value set; native branch-to-equation correspondence is manually argued in PROOF.md. The grammar's 18 handwritten examples and 11,110 finite representative words check the definition's structural properties. They do not exhaust arbitrary strings or independently verify the native relation. The general termination, original-byte partition, ownership/result propagation and length bound are manual inductive arguments.

There is no hidden assumption that normal return from an opaque allocator proves prefix preservation or that an error factory returns nonzero. Those are either explicit storage premises or deliberately unqualified result words. Source and output nonaliasing, canonical encoding, stable metadata, successful allocation/growth and ordinary preserving callees remain material limits of the result.
