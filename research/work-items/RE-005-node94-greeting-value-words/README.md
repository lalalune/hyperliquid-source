# RE-005: greeting value words and ordered failure state

A32byte decoded result does not imply a32byte wire read. The actual greeting
map's value wrapper25587d0 calls2558ee0 twice, then consumes a raw byte.
Each inner result is four independently variable-width unsigned words. The
paired result has65logical payload bytes but consumes9..73wirebytes, with
fixed mode1 charges32,32,1 and errors retaining already reached stores/cursor.
This closes that aggregate composition, while crediting existing scalar sites.

Base966865f1637a29ce75b019e1bf11d5529cc6f519; target node94 is91774280bytes,
SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Two aggregate FDEs total1607bytes/409GNUrows; scalar common/Reader/error
context makes the retained identity denominator5completeFDEs/2173bytes/
576rows. This is identity/context, not new recovered-byte credit. Every raw
GNU2.42/LLVM18.1.3 byte partition, complete FDE/CIE, selected initial RELA,
direct transfer, five dispatch tables and two diagnostic Locations/paths is
retained. No byte masks or omissions. No runtime pointer value is asserted.

In the admitted mode QWORD exactly1, each four-word operation charges32
before reading. Overflow preserves C; an exceeded limit retains C+32. After
admission the later guard conditions follow from C>=32 and C<=L with stable
helper state. Words1..3 inline the scalar fast/slow selector; word4 calls
2973b90, which itself chooses the same fast path when remaining>8. Thus word4
is not always a consuming Reader. Nonminimal integer encodings are admitted.
Fast rejected FE/FF leaves the cursor, whereas slow rejection consumes its
marker and has a different expected-type code. Short extensions consume only
their marker. Earlier words and charge stores survive every error.

The paired wrapper keeps word order across both blocks. After their success,
the raw byte charge happens before its availability test; all256byte values
are accepted. Defined success cells are outer tag0, eight u64 words at+8
through+64, and raw byte at+72 (decimal offsets). Errors compare only active
logical cells. The final-byte budget join also physically writes a word1 at
+16; that inactive kind2 payload and all other padding are excluded, rather
than assigning semantics to a wide copy of uninitialized bytes.

PROOF.md is the unchanged manual draft before the checker. Its future-tense
qualification checklist and370PR inventory describe that earlier stage;
VALIDATION.json and actual receipts describe qualification afterward. The
selection refresh read375openPRbodies over four non-atomic pages, with no
focused aggregate match.16053distinct mathematical inputs were frozen before
the parser/checker:3441four-word and12612paired-value cases, including all256
trailing-byte values, basis/threshold words, nonminimal widths, every selected
truncation, fast/slow invalid markers and charge/limit/overflow boundaries.
Expectations are constructed from known values and field boundaries; the
separate checker parses the selected protocol. Fourteen wrong aggregate rules
must disagree. These are mathematical predictions, never captured outputs.

CanonicalRE-005-bincode-varint owns scalar sites including2558ee0's first
table; RE-005 slow-widths and peer1365 own scalar Reader/wrapper/error context.
Peer1454 byte/bool and1535 fixed20/fixed32 primitive scope remain credited.
Canonicalstream-msg-codecs-94 owns generic greeting/hash schema. Peer1497
owns the specialized owned-byte collection semantics also cloned by2891c30;
that clone is deliberately not a new primitive here. Its source is not used.
The author's1723 covers the response envelope and excludes this selector0
payload. Generic MIT static tools reuse author1607/1723, without a runtime
dependency on another open PR or copied unlicensed inferred implementation.

The actual map2890b60 is caller context only. Its96-per-entry reservation,
key/entry insertion, nonempty map/drop/allocator/split behavior, the possible
small-limit single-leaf bound, full greeting schema and connection remain
unqualified. The admitted theorem is only mode1 under stable disjoint valid
input/output/state and ordinary preserving helper calls. It makes no claim
about other raw modes, nominal signature/hash types, native ABI, faults,
concurrent mutation, captured execution, compiler/Rust build, hosted CI or
complete component gate. All gates and recovered-byte registries stay unchanged.

Reproduce with an authenticated non-executable node94 and fresh outputs:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimizedPython, compare exact receipts and the Linux replay of the
Windows-frozen corpus. Rootdoctor/verify/catalogue-check/reproduce results
are retained. Fullmake test includes captured-instruction evaluators outside
static authorization and is NOT RUN. New independent code/docs are MIT;
captured artifact excerpts retain their original rights.
