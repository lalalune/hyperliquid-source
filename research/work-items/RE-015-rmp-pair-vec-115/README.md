# RE-015: rmp-serde newtype(Vec<(Option<String>, Option<String>)>) serializer and its element/str/header path (node #115)

This packet makes it possible to rebuild, as one executable Python model, the MessagePack writer of a vector of
`(Option<String>, Option<String>)` pairs: the `_ExtStruct` rejection, the u32 test that picks "array header first"
or "0x80-byte counted compound", the pair as a two-element array (`0x92`, then `0xc0` or a str per field), the
str header forms, the amortized `Vec<u8>` growth on every push, and the buffer allocation/release. The model was
checked against the real bytes of 10 functions on 11,000 cases with 0 mismatches, and 44 of 44 negative controls
were detected.

- Component ID: `constants` (RE-015 serializer work)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: lalalune/hyperliquid-source main `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source used
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp-serde / `Option<String>` names)
- Scope included: Vec body `0x2274a90`, pair bodies `0x2274810` (outer serializer) and `0x226ca20` (compound); they
  run for real together with `0x25e7940` (array header), `0x25e8750`/`0x25e8bf0` (str writers),
  `0x22997f0`/`0x22999e0` (pair end), `0x227e2e0` (Compound::end) and `0x231e050` (RawVec reserve).
  Excluded: the two other-shape bodies `0x2270910` and `0x22755b0` (see Next), progress gates.

## Reproduce

From the repository root (Python 3 standard library only; the binary is never executed):

```
python3 tools/rmp_pair_vec_115.py --out research/work-items/RE-015-rmp-pair-vec-115
python3 -m unittest tests.test_rmp_pair_vec_115
```

## Evidence

- `cases-sample.tsv`: every second case of each role (vec body, pair-b, pair-a): name, length, fault event, room,
  output length and hash, result words, abbreviated event list.
- `controls.tsv`: 44 negative controls (10 model mutants, 30 one-bit immediate flips in the three bodies, 4
  range/digest controls), all detected; 18 further immediate flips were equivalent and are not counted.
- `summary.json`, `measure.json`: totals and the output digest. `MANIFEST.sha256`: file hashes.
- Observations from the bytes: `0x2274810`/`0x226ca20` compare a 10-byte name with `_ExtStruct` and return the
  static-str error; the vec body passes the static 0x16-byte name at `0x5f178d` to every element call; the vec
  body tests `n >> 32` (u32 split), walks `n * 0x30` mod 2^64 down by 0x30, mallocs 0x80 and counts elements in a
  u32 compound word.

## Implementation and comparison

`tools/rmp_pair_vec_115.py` holds the model (`model`, `m_vec`, `m_pair`, `m_str`, `Vec`) and an x86-64 evaluator.
Only `finish_grow` (`0x231dc90`), memcpy, malloc and sdallocx are contract stubs. Failures are injected at the k-th
call of the header writer, str writers and element serializers; the model predicts the error record
(`ERR_TAG`, w1, w2), the buffer release and which events happen. Compared per case: appended bytes, final
Vec<u8> capacity, result words, ordered events (hdr/str/pair calls with compound count, length and config word,
grow steps, malloc/free), callee-saved registers and unchanged inputs.

## Results and limitations

- 11,000 cases (vec 6,000, pair-b 2,500, pair-a 2,500), 0 mismatches, 44/44 controls, 14 unit tests.
- Limits: strings of 2^32 bytes or more and element counts of 2^32 or more are not run end to end (counts of
  2^32/2^31 are tested only with an early element failure; wrapped lengths `m + j*2^60` cover the walk).
  `finish_grow` is a contract stub (new capacity honoured, data copied). The model grows the output per append
  operation (marker byte, length bytes, payload) and this matched the bytes on every case, but the reserve
  policy inside the str writers is established only through those cases.
- Next question: the other-shape bodies `0x2270910` (979 B) and `0x22755b0` (1152 B), and the element serializer
  stubs of the remaining Vec bodies.
