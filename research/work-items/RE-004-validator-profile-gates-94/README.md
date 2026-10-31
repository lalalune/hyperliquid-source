# RE-004: validator profile gate: commission bps, name and description lengths, IPv4 rule in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the order of the tests, the status text and the arithmetic on the words; inference for the field names and for what the chain set holds; unresolved items are listed under limits
- Scope included and excluded: included are the gate `0x3bfcbc0` and its only caller `0x3991f70`, run as real bytes, plus fixed byte rows of `0x3994f20` that feed them. Stubs here: the chain table accessor (slot `0x57732e8`), the free (slot `0x576e010`) and the 20-byte compare (slot `0x576e488`). Excluded: running `0x3994f20` itself, the action decoder, what happens after the scan, and readers of the stored commission.

## Reproduce

```
python3 tools/validator_profile_gates.py --out research/work-items/RE-004-validator-profile-gates-94
python3 -m unittest tests.test_validator_profile_gates
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about a minute.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact: `0x3bfcbc0..0x3bfcdba` (132 instructions) and `0x3991f70..0x399253d` (318). The gate's only call site is `0x39920ce` through slot `0x5776248`, whose RELATIVE target is the gate (`gate-slot.tsv`). The scan has two direct callers, `0x3995372` and `0x3995b19`, both in `0x3994f20` (`handler-pins.tsv`).

Gate arguments: `rdi` output, `rsi` profile `P`, `dl` set flag, bit 0 of `cl` "previous value present", `r8` previous value. Profile fields read here (`P`, `0x58` bytes):

| Offset | Word | Used as |
|---|---|---|
| `+0x00`, `+0x08`, `+0x10` | capacity, pointer, length | name |
| `+0x18`, `+0x20`, `+0x28` | capacity, pointer, length | description |
| `+0x30` | u64 | commission, `x` below |
| `+0x38` | 20 bytes | signer |
| `+0x4c` | byte | address tag |
| `+0x4d` | 4 bytes | IPv4 octets `a.b.c.d` |

Status text is in the Display table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x120` | Validator IP address must be global |
| `0x121` | Validator name must be between 1 and {50} |
| `0x122` | Validator description must be between 1 and {1000} |
| `0x123` | Validator commission must be between 0 and 100%. If commission increases, it cannot exceed 1%. |
| `0x124` | Validator IP already in use |
| `0x125` | Validator signer already in use |

`{50}` and `{1000}` are u64 literals at `0x20b0f8` and `0x20b0d8`, read by the format arm.

Gate order, first failure wins:

1. If bit 0 of the address tag is clear and the set flag is 0 and the address is in the refused set below: `0x120`.
2. Name length outside `1..=50`: `0x121`. Computed as `len - 51 >= -50` unsigned, so length 0 and every length above 50 fail, up to `2^64-1`.
3. Description length outside `1..=1000`: `0x122`.
4. `x > 10000`: `0x123`.
5. `limit = previous` if bit 0 of `cl` is set, else `10000`. `x > limit` and `x >= 101`: `0x123`.

On success: tag `0x186`, and `P[0..0x58]` goes to output `+8`. On failure: only the tag word is written, and both strings are freed if their capacity is not 0. So the bound is on basis points with 10000 as 100%, and step 5 reads exactly as the text: a rise above the stored value may not end above 100 bps. `x <= previous` always passes step 5 and so does `x <= 100`. With no previous value step 5 cannot refuse, since step 4 already holds `x <= 10000`.

`handler-pins.tsv` pins the feed in `0x3994f20`. The register path clears `r9d`, so no previous value. The change path sets `r9d = 1` and passes the word at record `+0x30` on the stack; a patch tag of 0 keeps the stored word as `x`. Before the scan, the change path also has patch bounds of its own: a name patch of 101 or more bytes and a description patch of 1001 or more bytes give `0x143`, and a commission patch above `0x0ccccccccccccccb` is refused at `0x3994fc2`.

Refused IPv4 set, proved for all `2^32` addresses (`ip-refused-blocks.tsv`, 51512319 addresses):

| Block | Addresses |
|---|---|
| `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8` | `2^24` each |
| `169.254.0.0/16`, `192.168.0.0/16` | `2^16` each |
| `172.16.0.0/12` | `2^20` |
| `192.0.0.0/24` less `.9` and `.10` | 254 |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | 256 each |
| `255.255.255.255` | 1 |

Proof shape. The tool walks every path of the real rows from the load at `0x3bfcbd8` to the two exits, tracking which address octets each result byte reads, and forks at each test (143 paths, `ip-paths.tsv`). The tests divide the octets into classes (`ip-octet-classes.tsv`): 11, 7, 6 and 3 classes, where every value of a class gives the same answer to every test. One point of each of the 1386 class products is held against the walker tree, the rule list and a real run of the bytes. The class sizes multiply out to exactly `2^32`. The walk with the set flag at 1 has no refusing path.

The two lengths and `x` meet only add, compare and conditional rows between `0x3bfcc87` and the success copy (`limit-window.tsv`). So each length has the three pieces in `length-pieces.tsv`, and both ends of each piece walk the same rows with the same status. `x` and `previous` are only compared, with each other and with 101 and 10000, so a grid of 15 values on each side reaches every order of the four.

Scan `0x3991f70`, arguments `rdi` output, `rsi` state `S`, `edx` chain byte, `rcx` validator (20 bytes), `r8` profile, `r9` flag, stack word previous value:

1. Slot `0x57732e8` with the chain byte gives `(root, height)` of a set of 20-byte keys (node keys at `+0x8`, length `+0xe6`, edges `+0xe8`). The set flag is whether the validator is in it. A zero root gives 0.
2. The gate runs on a copy of the profile. A refusal goes out, with `out+2..0x60` copied from an untouched stack area.
3. In key order over the map at `S+0x150` (keys at node `+0x3d0`, values of `0x58` bytes at `+0x8`, length `+0x4ae`, parent slot `+0x4ac`, edges `+0x4b0`, count at `S+0x160`), the validator's own row is skipped. For each other row: if the row's tag byte `+0x4c` equals the profile's and the address matches, `0x124`. With tag 0 all four octets are compared; with any other tag only the first byte at `+0x4d` is. Then an equal signer gives `0x125`. So inside one row the IP test is first, and between rows key order decides. Both refusals free the strings.
4. Success is tag `0x186` and the `0x58` profile bytes at `out+8`.

Reference compare, `l1/exchange/handlers/17_c_validator.rs`. Its `normalize_profile` leaves the gate as a comment ("The precise checks are buried in that helper"), and this packet is those checks. Other differences from bytes:

- `MAX_NAME_LEN = 100` is only the patch bound `0x143` on the change path. The rule that holds is `1..=50`, tag `0x121`. A name of 51 to 100 bytes passes the patch bound and is then refused. Length 0 is refused for both strings; the reference has no lower bound.
- `commission_bps` is `u16` there. The bytes compare a full 64-bit word.
- The scan there reads `validator_to_state` and only compares an IP when both sides have one. The bytes read the map at `S+0x150`, with values of the profile size.
- The foundation set there guards a comment. In the bytes the set flag skips only the IP rule.

## Implementation and comparison

not yet implemented. The tool holds a rule list `gate_tag` and `spec_run`, written apart from the bytes, that predicts the status, all fixture bytes and the event list of each run.

## Results and limitations

- 436 named cases and 400 generated cases: 0 mismatches, comparing fixture bytes, free arguments and event order, over real B-tree nodes up to height 17 with decoy rows in unused slots.
- All gate rows are reached. In the scan only the end-of-tree panic rows from `0x3992519` are not (`evidence.json`): a walk past the map count, which a count that matches the tree cannot reach.
- 211 byte edits on reached rows: 207 killed, 4 survived, each with a recorded reason (`mutations.tsv`). An unedited image must pass under the same step limit first.

Limits:

- `0x3994f20` is pinned by fixed bytes and read by eye; it is not run here, so the rows in `handler-pins.tsv` are bound to their meaning by reading, not by a test.
- Field names come from the status text, the action keys in `rodata-text.tsv` and the use of each word. The map at `S+0x150` as `validator_to_profile` was read by eye from the state serializer, not generated.
- The set behind slot `0x57732e8` is a stub. Reference label `is_foundation_self_signer` is unconfirmed: only its use as a set of 20-byte keys is observed, and its contents are not read.
- Tag 1 in the address byte is not named. Its gate skip and one-byte compare are observed; what it stands for is unresolved. Tag 2 in a stored profile is a fixture only, since the change path replaces a patch tag of 2 with the stored one.
- Trees here use zero-key chains for height, not the fill a real tree would have; the walk reads only length, edge and parent words, so shape has no other effect in these rows.
- The 7200-second cooldown in the reference was not checked here.

Next question: who reads the stored commission at record `+0x30`, and is the split of staged validator rewards a floor on `x / 10000`?
