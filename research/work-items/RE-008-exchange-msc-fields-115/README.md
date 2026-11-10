# RE-008: node #115 Exchange field `msc` (90th stage): `struct ExchangeMisc` and the simulate-panic pair

- Component ID: abci. Question: open PR #6095 placed Exchange field 58 `msc` at box +0x3908..+0x3a00 (layout A) and found that the simulate-panic pair from #6090/#6091 (+0x39a8 / +0x39b0) lies inside it. It left the field's type and sub-field names open. Open PR #6097 named the 16 Locus fields.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6091 and #6097 and does not depend on their files.
- Claim status: instruction bytes, jump-table entries, relocations, string bytes and call sites are observations. "Option", "None", "unset", "field" and "sub-field" are inferred labels from the serde/rmp-serde call shapes. The binary was not executed.
- Scope included: the Exchange element-58 decode, the `ExchangeMisc` deserialiser 0x490d9b0 (expecting record, field-identifier dispatch, the twelve duplicate-field name blocks, field 6's case and the output copy) and the field-6 decoder 0x47922c0's nil path. Scope excluded: the other eleven fields' output offsets, the identifier function behind slot 0x64e3a28, the use of `struct LocusMisc`, and every writer of the Exchange `msc` value after deserialisation. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/exchange_msc_fields_115.py --check
python3 -m unittest tests.test_exchange_msc_fields_115
```

The tool reads the ELF only. It does not execute the binary and does not start objdump or readelf. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: element 58 is `struct ExchangeMisc with 12 elements`

- The Exchange seq visitor 0x49da420 decodes element 58 at 0x49df2fa with 0x488f5c0, which calls 0x490d9b0 at 0x488f5e3. A result tag of 3 is an error (`cmp rcx,3` at 0x49df34c); a tag of 2 means the element is missing and leads to `invalid_length(0x3a)` (0x49df969).
- 0x490d9b0's expecting record 0x6497dc8 is relocated to 0x90f523 with length 36: `struct ExchangeMisc with 12 elements`. 0x490d9b0 has two direct callers (0x4828dcf, 0x488f5e3).

## Evidence 2: the twelve field names

In map form, 0x490d9b0 gets a field index from slot 0x64e3a28 (relocated to 0x349f540) and jumps through table 0x825408: indices 0..11 are fields, 12 skips an unknown key (0x490de0b) and 13 ends the map (0x4910706). Each field case tests its "already set" slot and branches to a duplicate-field block that loads the field name and its length (`mov qword [rsp+0x28], len`):

| Index | Name | Case | Name bytes |
|---|---|---|---|
| 0 | `uta` | 0x490dc51 | 0x90f505, 3 |
| 1 | `mou` | 0x490dfde | 0x90f508, 3 |
| 2 | `sgd` | 0x490decf | 0x90f50b, 3 |
| 3 | `sog` | 0x490df27 | 0x90f50e, 3 |
| 4 | `tde` | 0x490ddc7 | 0x90f511, 3 |
| 5 | `tce` | 0x490e08c | 0x90f514, 3 |
| 6 | `i` | 0x490e0d0 | 0x90e933, 1 |
| 7 | `mtpt` | 0x490df89 | 0x459e64, 4 |
| 8 | `pmc` | 0x490e1c8 | 0x90f517, 3 |
| 9 | `sre` | 0x490de33 | 0x90f51a, 3 |
| 10 | `vpv` | 0x490e124 | 0x90f51d, 3 |
| 11 | `aci` | 0x490dd81 | 0x90f520, 3 |

The ten three-letter names are stored back to back at 0x90f505..0x90f523, in index order, skipping fields 6 and 7.

## Evidence 3: field `i` is the simulate-panic pair

- Field 6's case tests `byte [rsp+0x238] == 3` (unset), calls 0x47922c0 (0x490e0e9), and stores the decoded u64 at rsp+0x408 (0x490e108) and the decoded byte at rsp+0x238 (0x490e118).
- 0x47922c0 writes byte 2 for a msgpack nil (`cmp al,0xc0` 0x47923bf, `mov byte [rbx+0x10],2` 0x47923c3); otherwise it stores the decoded u64 and byte (0x479240c, 0x4792410).
- The result is built at rsp+0x2e8 and copied to the output with a 0xf8-byte copy (0x490f33a..0x490f34a). `i`'s u64 goes to rsp+0x388 = msc+0xa0 (0x490f290). Its byte goes to rsp+0x390 = msc+0xa8 (0x490f298), with an unset field (3) replaced by 2 (`cmp cl,3` / `mov edx,2` / `cmovne` at 0x490f0b7..0x490f0c2).
- With `msc` at box +0x3908 (layout A, #6095), msc+0xa0 / msc+0xa8 are box +0x39a8 / +0x39b0: the stop height and stop byte from #6090/#6091.

Inference: `i` is an Option of a (height, flag) pair whose None is the byte value 2, so both a missing field and a nil decode to "no stop". This explains #6091's value 2 stores as None. It does not settle which of the two bit-0 polarities in #6091 is "armed".

## Implementation and comparison

The tool pins 21 instruction runs, 6 references, the expecting record and string, the 12 jump-table entries, 12 duplicate-branch targets and 12 name pointers with lengths. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: Exchange field 58 `msc` is `struct ExchangeMisc` with 12 fields named above; field 6 `i` holds the simulate-panic stop pair at msc+0xa0 / msc+0xa8.
- Limits: the output offsets of the other eleven fields are not bound; the identifier function behind slot 0x64e3a28 is not read; which value of the stop byte arms the panic (#6091) is not settled; `struct LocusMisc` (string at 0x452e80, no relocation) is not tied to a field; writers of the msc value after deserialisation are not mapped.
- Next lead: the remaining ExchangeMisc output offsets (rsp+0x2e8 layout) and the meaning of `i`'s byte at the six simulate-panic sites.
