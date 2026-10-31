# RE-006: from a book change to one line of `node_raw_book_diffs`

This packet shows that node #94 writes one `new`, `update` or `remove` row at exactly three small functions that also keep the book total size, and traces that row to the JSON line, so a reconstruction can emit the raw book diff stream from its slab insert, size change and slab removal, and print numbers the way the node does (f64, ten decimals, trailing zeros cut, at least one kept).

- Component ID: RE-006 (book state transitions), the raw book diff output from the book write to the file line
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. No file under `l1` in the reference holds the text `raw_book_diff`, so nothing here comes from it.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are row writers `0x42e8710`, `0x232c410`, `0x232c560` (new), `0x49e4f20`, `0x49e4de0`, `0x232e5a0`, `0x232e6e0` (update), `0x42e8860`, `0x232c6b0`, `0x232ca40` (remove), the row kind 2 arms of sinks `0x48547d0` and `0x48551e0`, mode switch `0x47ee2b0`, file writers `0x47028b0`, `0x47013b0`, `0x47037b0`, line writers `0x45b4d70`, `0x45ba320`, `0x45b19a0`, serializers `0x47ef630`, `0x47ee890`, `0x48653c0`, `0x4a98d90`, `0x47f04c0`, `0x47efb40`, `0x4a7b210`, `0x4a7fc00`, f64 text `0x4a7a460`, `0x4c27fa0`, `0x37e5350`. Real bytes with no mutants: `0x42e85c0` and `0x42e8bf0`, whose addresses #47 names as insert and delete accounting with no word about the row, and every field writer below the serializers. Address hits that are not this question: `0x49e4f20`, `0x49e4de0`, `0x232e5a0`, `0x232e6e0`, `0x42e8860`, `0x232c410`, `0x232c560`, `0x232c6b0`, `0x232ca40` are rows in the saturating line lists of #149 and #234, `0x49e4f20` is a named callee in #750, the sinks are in #851 (a byte binding with no semantic claim) and in #1036, `0x47ee2b0` is a callee row in #851. Excluded: the book hosts that call the writers, the slab insert body, the date text behind the path, and the rows of other kinds in the same flush.

## Reproduce

From the repository root:

```
python3 tools/raw_book_diff_output.py --out research/work-items/RE-006-raw-book-diff-output-94
python3 -m unittest tests.test_raw_book_diff_output
```

The tool takes about 60 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `row_writers.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | Functions |
| --- | --- |
| Book write, one row kind 2 | 12 writers in `row_writers.tsv`, four each of new, update, remove |
| Row flush | `0x432a100` (perp, table `0x6eed68`, kind 2 arm `0x432a234`), `0x432a990`, `0x4d8fce0` (spot) |
| Sink arm | spot `0x48547d0` arm `0x4854950`, perp `0x48551e0` arm `0x4855361` |
| Mode switch | `0x47ee2b0` on object `+0x5b0` |
| File | `0x47028b0`, `0x47013b0`, `0x47037b0` |
| Line | `0x45b4d70`, `0x45ba320`, `0x45b19a0` |
| JSON | record `0x47ef630`, diff `0x47ee890`, envelopes `0x47f04c0`, `0x47efb40` |

### Row writers

Each writer is 314 to 906 bytes. Copies come in 0x268 and 0x278 byte row widths, and the four of a kind ran the same specification.

| Kind | Tag `+0x08` | Words | Book side effect |
| --- | --- | --- | --- |
| new | 0 | `+0x10` size | total `+=` size, saturating, then slab insert of the 0xf8 slot; returns the old free head |
| update | 1 | `+0x10` old, `+0x18` new | nothing at all when new equals old; else slot `+0xc8` = new, total `-=` old then `+=` new |
| remove | 2 | none | absent or vacant key (word 2) writes nothing and returns word 2; else slot becomes vacant, count saturates down, free head = key, total `-=` size |

Every row: `+0x00` = 2, `+0x20` px (slot `+0xa0`), `+0x28` asset (argument), `+0x30` oid (slot `+0xd8`), `+0x38` 20 byte user (slot `+0xe0`), `+0x4c` side (slot `+0xc2`). Total underflow writes the recorder line and stores 0 (update then adds new), overflow writes the recorder line and stores `u64::MAX`. The row goes in before the slab changes in `new`, after them in `remove`.

### Sink arms

Gate: object `+0x5b0` equal to `0x8000000000000000` skips the row with no clock read. Any other word goes on. Fields are read from row `+0x08..+0x4c`, then the clock.

| Market | Coin text | px divisor | size divisor |
| --- | --- | --- | --- |
| spot | see below | `10^(quote +0x49 - base +0x48)`, panic when negative | `10^(base +0x48)` |
| perp | row `+0x08`, length `+0x10` in meta list `+0x08`, stride 0x30 | `10^(6 - row +0x2a)`, panic at 7 or more | `10^(row +0x2a)` |

Perp asset: `asset / 10000` must equal meta `+0x30` and `asset % 10000` must be inside the list, else panic. Spot asset indexes pairs at meta `+0x168` (stride 0x20, `+0` base, `+8` quote), tokens at meta `+0x180` (stride 0xe8).

Spot coin text: slot `0x57738c8` is asked about the base token. A second byte of 0 or 1 makes the coin `#` followed by `10 * word + byte`, with multiply and add saturating and a further saturating add and subtract of 1e8. Otherwise index 0 is the fixed `PURR/USDC`, an index below 1e8 is `[at]index`, and an index at or above 1e8 is `#(index - 1e8)`.

Sizes and price turn into f64 through the u64 to double sequence, then a divide by table `0x6f7470`. The 0x58 byte record: `+0x00` tag, `+0x08` first, `+0x10` second, `+0x18` coin String, `+0x30` oid, `+0x38` px, `+0x40` user, `+0x54` side. The words a tag does not use keep stale register values.

### Output modes

Constructor `0x47f1590` reads byte `+3` of its config (the block for this name runs only if it is set), and builds buffer name `node_raw_book_diffs`. Byte offsets show the finished buffer landing at object `+0x5b0`: stack `+0x1080` to `+0x810`, block `+0x680` to object `+0x420`. Bytes `+9` and `+0xa` both set panics with `cannot set both batch_by_block and stream_with_block_info`.

| Option | Directory suffix | Word at buffer `+0xb0` | Effect |
| --- | --- | --- | --- |
| neither | none | `1 << 63` | `0x47028b0` writes one record per line |
| `batch_by_block` | `_by_block` | Vec capacity | record kept, stride 0x58, grown through slot `0x5776a50` |
| `stream_with_block_info` | `_streaming` | `(1 << 63) + 2` | block date word 0 drops the record; else `0x47013b0` writes one `events` line |

Block end `0x48576a0` takes the Vec of the batch mode and calls `0x47037b0` with it, once per call, also with an empty Vec (read, not run). `local_time` is the clock, plus 40 ms when object byte `+0xa78` is set, with the day carried through slots `0x576e8a8`, `0x576e8b0` and panic `NaiveDateTime + TimeDelta overflowed`.

### File rotation

Three writers of 753 bytes differ only in the line callee. Buffer `+0x48` holding `1 << 63` writes nothing. Time words are date, seconds, nanoseconds. Seconds at `0xe1000` or above panic through `Result::unwrap`, at 90000 or above panic `assertion failed: hour <= 24`. Hour = seconds / 3600, through `0x91a2b3c5 >> 43`.

Byte `+0xa8` = 1: a new file when hour (`+0xa9`) or date (`+0x98`) changed, path `{dir}/hourly/{date}/{hour}`. Any other byte: a new file when the date changed, path `{dir}/{date}`, and `+0xa8` stays. The last time goes to `+0x9c`. Flush runs only when byte `+0xaa`, the global byte `0x5788312` and an open file agree.

### JSON

In this packet `[at]` stands for the byte 0x40 in coin text.

Real bytes printed these four lines (time fields are placeholders because their writer is stubbed):

```
{"user":"0x00112233445566778899aabbccddeeff01234567","oid":99,"coin":"BTC","side":"A","px":"3000.25","raw_book_diff":{"new":{"sz":"1.5"}}}
{"user":"0xf0e1d2c3b4a5968778695a4b3c2d1e0f10203040","oid":99,"coin":"BTC","side":"B","px":"3000.25","raw_book_diff":{"update":{"origSz":"2.5","newSz":"0.125"}}}
{"user":"0x00112233445566778899aabbccddeeff01234567","oid":99,"coin":"[at]107","side":"A","px":"3000.25","raw_book_diff":"remove"}
{"local_time":"L505152535455565758595a5b","block_time":"T707172737475767778797a7b","block_number":999,"events":[{"user":"0x00112233445566778899aabbccddeeff01234567","oid":99,"coin":"BTC","side":"A","px":"3000.25","raw_book_diff":{"new":{"sz":"1.5"}}},{"user":"0x00112233445566778899aabbccddeeff01234567","oid":99,"coin":"BTC","side":"A","px":"3000.25","raw_book_diff":"remove"}]}
```

Keys with record offsets are in `json_keys`. The 0x80 byte line buffer grows as needed and the line ends in `\n`. Side byte 0 prints `B`, 1 prints `A`. A word of tag 2 or above prints `remove`.

f64 text (`0x4c27fa0`): template `0x20ad58` is `{:.10}`, then `0x37e5350` cuts trailing zeros and stops at `.0`, and `-0.0` becomes `0.0`. So 2.0 prints `2.0`, 1e-11 prints `0.0`, and a size above 2^53 loses low bits on the way.

### Inferences

Slot `+0xc2` 0 is the bid side, from the text `B`. The three kinds are the only places a book order changes: a whole `.text` byte scan for a stack built row head finds exactly these 12 functions (`row_scan`). A row built another way would not show (unresolved). Row writers `0x232c...` sit in first copy hosts `0x26e81c0`, `0x26ebdc0`, `0x26de3d0`, `0x26df430`, whose flush is not traced here. The date text behind the path is the Display of a word and its format is not read.

### Unresolved

What sets object byte `+0xa78`: the constructor stores `word != None` from slot `0x576efe8`. Which row a matched maker writes in which order is in the hosts. Slot `0x57738c8` is stubbed, so the `#` id is a pair of words here, not a proved outcome id.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes and compares them with a separately written specification. The specification is a model for this comparison, not a reconstruction of the Rust source.

## Results and limitations

| Measure | Value |
| --- | --- |
| Cases | 320 |
| Mismatches | 0 |
| Instructions stepped | 185,590 |
| Stepped / total: new row writer, 0x278 rows `0x42e8710` | 69 / 84 |
| Stepped / total: new row writer, 0x268 rows `0x232c410` | 69 / 84 |
| Stepped / total: new row writer, 0x278 rows `0x232c560` | 69 / 84 |
| Stepped / total: update row writer, 0x268 rows `0x49e4f20` | 68 / 74 |
| Stepped / total: update row writer, 0x278 rows `0x49e4de0` | 68 / 74 |
| Stepped / total: update row writer, 0x278 rows `0x232e5a0` | 68 / 74 |
| Stepped / total: update row writer, 0x268 rows `0x232e6e0` | 68 / 74 |
| Stepped / total: remove row writer, 0x278 rows `0x42e8860` | 159 / 174 |
| Stepped / total: remove row writer, 0x268 rows `0x232c6b0` | 160 / 175 |
| Stepped / total: remove row writer, 0x278 rows `0x232ca40` | 160 / 175 |
| Stepped / total: output mode switch `0x47ee2b0` | 156 / 178 |
| Stepped / total: rotating file, one record per line `0x47028b0` | 148 / 161 |
| Stepped / total: rotating file, streaming line `0x47013b0` | 148 / 161 |
| Stepped / total: rotating file, batch line `0x47037b0` | 148 / 161 |
| Stepped / total: one record line `0x45b4d70` | 63 / 85 |
| Stepped / total: streaming line `0x45ba320` | 63 / 85 |
| Stepped / total: batch line `0x45b19a0` | 63 / 85 |
| Stepped / total: record serializer `0x47ef630` | 71 / 86 |
| Stepped / total: raw_book_diff value `0x47ee890` | 111 / 157 |
| Stepped / total: raw_book_diff key wrapper `0x48653c0` | 6 / 14 |
| Stepped / total: raw_book_diff field `0x4a98d90` | 57 / 101 |
| Stepped / total: streaming serializer `0x47f04c0` | 57 / 72 |
| Stepped / total: batch serializer `0x47efb40` | 57 / 72 |
| Stepped / total: events field, one record `0x4a7b210` | 76 / 136 |
| Stepped / total: events field, all records `0x4a7fc00` | 101 / 167 |
| Stepped / total: f64 as a string `0x4c27fa0` | 66 / 75 |
| Stepped / total: trailing zero trim `0x37e5350` | 59 / 104 |
| Stepped / total: f64 field `0x4a7a460` | 76 / 101 |
| Stepped / total: perp sink, row kind 2 arm only `0x48551e0` | 131 / 134 |
| Stepped / total: spot sink, row kind 2 arm only `0x48547d0` | 184 / 184 |
| Stepped / total: new row writer, the 0x268 copy: address named in #47, run with no mutants `0x42e85c0` | 69 / 84 |
| Stepped / total: remove row writer, the 0x268 copy: address named in #47, run with no mutants `0x42e8bf0` | 159 / 174 |
| Mutants killed / survived / unreached | 1029 / 32 / 209 |

The first compare with every stub in place had 8 misses in 315 cases. 5 came from a spec that took any second byte as an outcome (only 0 and 1 count, which the bytes showed), 3 from a spec that freed an empty coin, and the far pair fixture needed a fake table base. Each was fixed against the bytes. Every surviving mutant has a reason in `mutations.tsv`. They fall into dead stores, buffer capacities that are never 0, state bytes compared with one value only, error arms no run takes, and two saturating arms that one number cannot tell apart. An earlier pass left 124 survivors, and 92 of them were harness gaps (buffer limits, copy sizes, panic text lengths, file bytes, exact fit lines). The stubs now check those.

Unreached mutants sit in allocator failure, serializer error, panic and unwind arms, and the multi-byte arm of the trim. State here is fake: a real node was not run, and no real book was read. `0x48576a0` is read and its calling bytes pinned, not run.
