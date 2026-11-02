# Input-only future client protocol

This protocol is frozen before any Rust/client source. The Python oracle emits
ASCII LF-terminated records. Every numeric word is exactly16 lowercase hex
digits, interpreted as unsigned64; no decimal floats, locale or host NaNs.
An input line contains these words in order:

```
id asset oracle target scale mode member
first_entry_count second_entry_count common_slot_count
    (key_raw active head) * first_entry_count
    (key_raw active head) * second_entry_count
    (tag quantity continuation next) * common_slot_count
```

There is one shared slab/count for both trees, exactly as native RDI is shared
across both calls. There is no hidden per-side bound. Case builders may embed
separate finite chains by renumbering valid indices and mapping every invalid
initial/later index to U64_MAX before evaluation. Shared-slot cases use the
same logical slot from both trees. This is input construction, not a public
API transformation.

All of the above occupies one physical line; indentation/newlines here only
describe its variable-length structure. `key_raw` is the two's-complement
representation of an i64. Scale, mode and active must fit u8; tag must fit u32;
member must be0 or1. Counts must fit the client's actual finite input and
platform size. No trailing words, missing words, duplicate output, unexpected
arguments or malformed lexical forms are accepted. Parser/resource refusals
are harness errors, not native/API error values. Empty input is valid and
produces empty output. The client is supplied **only inputs**, never expected
files, labels, oracle code, SHA-selected answer tables or false-model outputs.

One output line per input has the same id and one of these exact forms:

```
id N asset 0000000000000001 raw_oracle
id V premium_bits first_impact second_impact asset 0000000000000000 premium_bits
id E SCALE
id E TARGET
id E CYCLE1
id E CYCLE2
```

`N` represents absence; inactive native premium/second words are absent from
the protocol. `V` carries active premium fields followed by the selected
record. `E` is separately identified new safe policy, never a native ordinary
result or panic payload. No selected record exists on refusal. The protocol
does not expose a diagnostic trace or claim that output proves the otherwise
unobservable two-impact ordinary call order.

`corpus/inputs.txt.gz` holds the exact future input stream; `expected.txt.gz` the
independently authored answer stream; `cases.tsv` provides category/result
labels; `report.json` retains their identities and22 first-difference witnesses.
Both streams are deterministic gzip with raw and stored SHA256/byte counts.
For inspection use `gzip -dc corpus/inputs.txt.gz` or
`gzip -dc corpus/expected.txt.gz`; no data transformation or output masking is
performed. The local `.gitattributes` keeps these small evidence archives as
real repository bytes rather than LFS pointer substitutions.
Twenty witnesses concern ordinary value models; two (`scale-after-oracle`,
`short-circuit-zero`) concern the explicitly separate safe policy. These are
mathematical false models, not compiled production mutants. No Rust exists
at the pre-code freeze. Later validation must retain real compiled-mutant
outputs and label survived or noncompiling mutants honestly.

Every generated input feeds logical books into the prefix oracle. The corpus
does not inject impact results or impossible floating inputs. Oracle unsigned
conversion boundaries include the whole raw u64 range; admitted active impact
values remain outcomes of the capped whole-product walk. Numeric cases cross
all seven scales, both mode classes (including255), membership, clamp sides,
integer conversion ties and signed keys. Book cases distinguish actual order,
initial/later invalid links, dword tags, full-width continuation, saturation,
zero-price quantity, early exhaustion, terminal floors, unused data and cycles.

Regeneration is deterministic with no platform random generator. The PRNG's
specified64-bit LCG only chooses finite inputs; expectations use exact rational
rounding and unbounded prefix sums. The portable verifier compares all four
generated files byte-for-byte under ordinary and optimized Python, varied hash
seeds and time zones. This finite evidence supports but does not replace the
manual native/numeric proof or later source arithmetic proof.
