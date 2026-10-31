# RE-006: from a book row to one line of `node_order_statuses` and `node_twap_statuses`

This packet shows how node #94 turns a status byte written by the book hosts into a JSON line, with the 36 status names, the pending vector that holds rows until an inner word 4 writes them out, the three output modes and the block end drain, so a reconstruction can emit both status streams from its book transitions in the same order and text as the node.

- Component ID: RE-006 (book state transitions), the order status and TWAP status output from the row to the file line
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. Nothing here comes from the reference.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are handlers `0x47f1100`, `0x47f0d10`, mode switch `0x47ed990`, leftover rows `0x44c82e0`, the entry and the two status arms of block end `0x48576a0`, rotations `0x4703ab0`, `0x47034b0`, `0x47052b0`, `0x4701fb0`, `0x4705eb0`, `0x47046b0`, line writers `0x45b3ef0`, `0x45b3220`, `0x45b3ba0`, `0x45b9ab0`, `0x45b2c20`, `0x45bc6c0`, serializers `0x47ef4d0`, `0x47efda0`, `0x47efc70`, `0x47f0130`, `0x47f05f0`, key wrappers `0x48652c0`, `0x4865380`, fields `0x4a9f620`, `0x4a98b80`, `0x4a935d0`, `0x43270a0`, `0x4a78820`, `0x4aa1d20`, `0x4a8cff0`, `0x4a96890`. Real bytes with no mutants: text field `0x4a9a1a0` (its table is a row in #161, #212, #354, #763, which read it for cancel reason names, not for this line), address field `0x4a83200` (a row in #1036), the sink tail jumps. Stubbed: order object `0x49e8b60`, the TWAP object `0x47ef250` (subject of #265), date text, row drop `0x47e6190`. The 25 host functions in `status_row_sites.tsv` are only named as locations of a byte pattern. Their bodies are other packets (#47 and others) and nothing here reads their insert or cancel logic. Other address hits, none on this question: sink `0x48547d0` is a row in #650, #851, #941 and #1036, sink `0x48551e0` in #1036, constructor `0x47f1590` in #245 and #348 (db code tables), and its bytes here are pinned, not run. Excluded: the JSON of the order record, and the other streams of the same object.

## Reproduce

From the repository root:

```
python3 tools/order_status_output.py --out research/work-items/RE-006-order-status-output-94
python3 -m unittest tests.test_order_status_output
```

The tool takes about 50 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `status_names.tsv`, `status_row_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | Order status | TWAP status |
| --- | --- | --- |
| Row head | 52 sites in 25 hosts, `status_row_sites.tsv` | not scanned |
| Sink tail jump | slot `0x5776b00` | slot `0x5776af8` |
| Handler | `0x47f1100` | `0x47f0d10` |
| Mode switch | `0x47ed990` on object `+0x740` | inline on object `+0x678` |
| File, stream, batch rotation | `0x4703ab0`, `0x47034b0`, `0x47052b0` | `0x4701fb0`, `0x4705eb0`, `0x47046b0` |
| Line | `0x45b3ef0`, `0x45b3220`, `0x45b3ba0` | `0x45b9ab0`, `0x45b2c20`, `0x45bc6c0` |
| JSON | `0x47ef4d0`, `0x47efda0`, `0x47efc70` | `0x47ef250`, `0x47f0130`, `0x47f05f0` |
| Block end | `0x48576a0` arm `0x4857f5d` | arm `0x4857d35` |

Sink tables `0x6fd33c` and `0x6fd35c` send row word 3 and 4 to arms that add 8 to the row pointer and jump through the slot.

### Row kind 3

The word after the head selects the variant:

| Inner word | Variant | Writers |
| --- | --- | --- |
| 2 | one status, no hash, held in the pending vector | 22 sites |
| 4 | write the pending vector out | 30 sites |
| any other (0, 1, 3) | a whole 0x118 byte row; the word is the builder tag | no site in the scan |

Row layout of 0x118 bytes, as stored:

| Offset | Size | Field | Key |
| --- | --- | --- | --- |
| `+0x00` | 8 | builder tag, low byte tested | `builder` |
| `+0x08` | 8 | fee word | `f` |
| `+0x10` | 20 | builder address | `b` |
| `+0x28` | 0xa8 | order record | `order` |
| `+0xd0` | 12 | time | `time` |
| `+0xdc` | 20 | user | `user` |
| `+0xf0` | 1 + 32 | hash flag and bytes | `hash` |
| `+0x111` | 1 | status byte | `status` |

A row with inner word 2 is packed eight bytes down: fields at `+0x08`, `+0x30`, `+0xd8`, `+0xe4`, status at `+0xf8`. The handler moves each field and stores 0 at `+0xf0`, so a pending row always prints `"hash":null`.

### Handler `0x47f1100`

Object `+0x740` equal to `1 << 63` closes the stream: the row is dropped (word 2 at `+0x30`, a whole row at `+0x28`, word 4 drops nothing). The clock is read next.

- Word 2 pushes onto the Vec at object `+0x408`, stride 0x118, grown through slot `0x5776a68`.
- A whole row goes straight to `0x47ed990`.
- Word 4 takes the Vec, resets it to capacity 0, pointer 8, length 0, and sends each row to `0x47ed990`. A row whose first word is 2 ends the walk. Rows after it are dropped through `0x447ded0` with no output. The buffer is then freed.

### Output modes

Word at stream `+0xb0`, on both streams:

| Word | Effect |
| --- | --- |
| `1 << 63` | file line |
| `(1 << 63) + 2` or above | one `events` line; block date word 0 drops the row |
| any non-negative word (Vec capacity) | row kept for the block end |

`local_time` is the clock, plus 40 ms when object byte `+0xa78` is set, with the panic `NaiveDateTime + TimeDelta overflowed` past the seconds range.

Block end `0x48576a0` returns at once when the block date `+0xa68` is 0. For a stream that is open with a Vec, it takes the Vec, resets it, calls the batch rotation once, also with no rows, then drops every row and frees the buffer. The third argument, low byte, flushes the file of each open stream.

### Constructor

`0x47f1590`: each block starts from a gate. The instruction after the gate jump stores the closed word in the stack slot of that buffer, and a 0xc8 byte copy moves the slot into the block copied to object `+0x420`. `buffers` in `evidence.json` lists the result: `node_order_statuses` at `+0x740`, `node_twap_statuses` at `+0x678`.

- Config byte `+4` gates `node_order_statuses`.
- Config byte `+2` gates `node_fills`. `node_twap_statuses` has no gate of its own: its block follows the `node_fills` block, and `0x47f191a` closes both. A node that writes no fills writes no TWAP statuses.
- Config byte `+8` set stores 1 in the global flush byte read by every rotation.

### TWAP handler `0x47f0d10`

The 0x88 byte row holds a String at `+0x00` and a second one at `+0x58`, whose capacity word has the niches `1 << 63` to `(1 << 63) + 2`. Closed stream (`+0x678` equal to `1 << 63`): second text freed, then first. Other paths free first, then second. The Vec path keeps both. Stream bytes `+0xb0` and block date match the order status modes, with the same 40 ms and the same panic. Inner words do not exist here: no pending vector.

### File rotation

Six writers of 753 bytes have one instruction shape (`rotation_shapes`), and six line writers of 323 bytes likewise (`line_shapes`). Hour limit 90000 s, `{dir}/hourly/{date}/{hour}` or `{dir}/{date}`, flush only when byte `+0xaa`, the global byte `0x5788312` and an open file agree.

### JSON

Real bytes printed these lines. Time values and the order value are markers because their writers are stubbed.

```
{"time":"Cb0b1b2b3b4b5b6b7b8b9babb","user":"0x00112233445566778899aabbccddeeff01234567","hash":null,"builder":null,"status":"filled","order":"O9091929394959697"}
{"time":"Cb0b1b2b3b4b5b6b7b8b9babb","user":"0x00112233445566778899aabbccddeeff01234567","hash":"0x11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7ac","builder":{"b":"0xf0e1d2c3b4a5968778695a4b3c2d1e0f10203040","f":7},"status":"canceled","order":"O9091929394959697"}
{"local_time":"L505152535455565758595a5b","block_time":"T707172737475767778797a7b","block_number":999,"events":[{"time":"Cb0b1b2b3b4b5b6b7b8b9babb","user":"0x00112233445566778899aabbccddeeff01234567","hash":null,"builder":null,"status":"filled","order":"O9091929394959697"},{"time":"Cb0b1b2b3b4b5b6b7b8b9babb","user":"0x00112233445566778899aabbccddeeff01234567","hash":null,"builder":null,"status":"triggered","order":"O9091929394959697"}]}
```

Key order: `time`, `user`, `hash`, `builder`, `status`, `order`. Missing hash and builder print `null`. A hash prints as `0x` and 64 hex digits, a builder as `{"b":"0x...","f":n}`. `json_keys` lists each key with its row offset. Stream and batch lines wrap rows in `local_time`, `block_time`, `block_number`, `events`, at row `+0x120`, `+0x12c`, `+0x118` for a single order status row, `+0x90`, `+0x9c`, `+0x88` for a TWAP row, and at header `+0x20`, `+0x2c`, `+0x18` for a batch.

### Status names

`status_names.tsv`: 36 bytes, read from the arms of table `0x7038dc` by a fixed byte pattern and confirmed by running every byte through the line. 0 `open`, 1 `filled`, 2 `canceled`, 3 `triggered`, 4 `rejected`, then cancel reasons 5 to 0x10 and reject reasons 0x11 to 0x23.

Of the 22 sites with inner word 2, 4 store byte 1 (`filled`), 3 store byte 3 (`triggered`), and 15 store a register.

### Inferences

The `f` word is a builder fee, from the key beside a builder address. Row field sources were read at two sites, `0x42f7e94` and `0x42ff9b9`, not run: order record from the record builder, time from a context word, user from the caller. At `0x42f7eb9` the register is the byte that earlier packets call a cancel reason, so the reason bytes passed to cancel functions reach this table as text. The other 14 register sites were not read one by one.

### Unresolved

The whole row arm, the only arm that can print a non-null hash, has no writer in this scan. The scan sees stack rows with word 3 stored by an immediate, so a row built another way would not show. Byte 0 (`open`) has no immediate site either: it comes from the whole row arm or from a register site, and this packet cannot say which. What sets object byte `+0xa78` is open.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes and compares them with a separately written specification. The specification is a model for this comparison, not a reconstruction of the Rust source.

## Results and limitations

| Measure | Value |
| --- | --- |
| Cases | 449 |
| Mismatches | 0 |
| Instructions stepped | 426,727 |
| Stepped / total: row kind 3 handler `0x47f1100` | 199 / 241 |
| Stepped / total: row kind 4 handler `0x47f0d10` | 197 / 215 |
| Stepped / total: status output mode switch `0x47ed990` | 131 / 153 |
| Stepped / total: pending rows left after the walk `0x44c82e0` | 33 / 58 |
| Stepped / total: block end: entry and the TWAP and order status arms `0x48576a0` | 232 / 235 |
| Stepped / total: status file rotation `0x4703ab0` | 148 / 161 |
| Stepped / total: status stream rotation `0x47034b0` | 148 / 161 |
| Stepped / total: status batch rotation `0x47052b0` | 148 / 161 |
| Stepped / total: twap file rotation `0x4701fb0` | 148 / 161 |
| Stepped / total: twap stream rotation `0x4705eb0` | 148 / 161 |
| Stepped / total: twap batch rotation `0x47046b0` | 148 / 161 |
| Stepped / total: status file line `0x45b3ef0` | 63 / 85 |
| Stepped / total: status stream line `0x45b3220` | 63 / 85 |
| Stepped / total: status batch line `0x45b3ba0` | 63 / 85 |
| Stepped / total: twap file line `0x45b9ab0` | 63 / 85 |
| Stepped / total: twap stream line `0x45b2c20` | 63 / 85 |
| Stepped / total: twap batch line `0x45bc6c0` | 63 / 85 |
| Stepped / total: status row serializer `0x47ef4d0` | 80 / 85 |
| Stepped / total: status key wrapper `0x48652c0` | 6 / 14 |
| Stepped / total: order key wrapper `0x4865380` | 6 / 14 |
| Stepped / total: order field `0x4a9f620` | 97 / 101 |
| Stepped / total: hash field `0x4a98b80` | 131 / 135 |
| Stepped / total: builder field `0x4a935d0` | 122 / 126 |
| Stepped / total: builder object `0x43270a0` | 69 / 74 |
| Stepped / total: status streaming serializer `0x47efda0` | 57 / 72 |
| Stepped / total: status batch serializer `0x47efc70` | 57 / 72 |
| Stepped / total: status events field, one row `0x4a78820` | 132 / 136 |
| Stepped / total: status events field, all rows `0x4aa1d20` | 162 / 167 |
| Stepped / total: TWAP streaming serializer `0x47f0130` | 57 / 72 |
| Stepped / total: TWAP batch serializer `0x47f05f0` | 57 / 72 |
| Stepped / total: TWAP events field, one row `0x4a8cff0` | 132 / 136 |
| Stepped / total: TWAP events field, all rows `0x4a96890` | 164 / 169 |
| Stepped / total: status text field: table 0x7038dc is a row in earlier packets, run with no mutants `0x4a9a1a0` | 237 / 241 |
| Stepped / total: address field: a row in #1036, run with no mutants `0x4a83200` | 105 / 109 |
| Mutants killed / survived / unreached | 1239 / 43 / 127 |

The first compare with every stub in place had 76 misses in 331 cases, all from the harness: 74 from a tail jump to a stubbed drop, 2 from the offset of the leftover row drop. Nothing in the spec changed. The first mutation pass left 58 survivors, and they led to 118 more cases: TWAP and block end date limits, helper call logs in the block end, a filler that pushes each line past its buffer, and a room sweep that puts exactly 3 free bytes before a `null`. One survivor pair came from a stub that repaired a buffer overrun with its own grow. The stub now tests room the way the real code does. Each remaining survivor has its reason in `mutations.tsv`.

Unreached mutants sit in allocator failure, serializer error, panic and unwind arms. State here is fake: a real node was not run, and no real book was read. The rest of block end `0x48576a0` is outside this packet. The block end runs with the other streams closed.
