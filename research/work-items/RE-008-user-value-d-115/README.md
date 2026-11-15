# RE-008: node #115 per-user value (112th stage): the D field is a date-keyed map with one-byte item keys

- Component ID: abci. Question: open PR #6239 found that the per-user value visitor `0x1a212f0` calls `0x18d4f40` for key `D` and keeps the result at output `+0x28`, with item size `0x18`. It did not read `0x18d4f40`. What does D hold, which keys does it accept, and do its keys have long names, as the p field has (`perp_to_position`, `n_open_positions`)?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6239. It does not depend on its files.
- Claim status: instruction bytes, jump-table entries, call targets, strings and offsets are observations. "Map", "struct", "date key", "default", "sort" and "small form" / "large form" are inferred labels. The binary was not executed.
- Scope included: the D decoder `0x18d4f40` (marker dispatch), its map visitor `0x27a95f0`, its array visitor `0x28197a0` and array element `0x1bd5ae0`, the collector `0x2dac950`, and the item value decoder `0x1be12b0`. Scope excluded: the body of the key decoder `0x17e3120`, the sort functions, the two collection builders `0x24d5580` and `0x23b17f0`, and the writer side of D. No gate changes.

## Result

| Part | Function | What it does |
|---|---|---|
| D decoder | `0x18d4f40` | fixmap, map16 (`0xde`), map32 (`0xdf`) go to the map visitor; fixarray, array16 (`0xdc`), array32 (`0xdd`) go to the array visitor |
| Map visitor | `0x27a95f0` | each key through `0x17e3120` with the 4-byte name `Date`; each value through `0x1be12b0`; entry `0x18` bytes: key dword `+0x0`, value `+0x8` |
| Array visitor | `0x28197a0` | each element through `0x1bd5ae0`, which calls the same `Date` key decoder and the same value decoder (a list of pairs) |
| Collector | `0x2dac950` | sorts by key; two equal adjacent keys give `duplicate key`; up to `0x40` entries keep the `(cap, ptr, 0, len)` form; more entries build a second form (tag `0x8000000000000000`) |
| Item value | `0x1be12b0` | a struct with key `a` (index 0) and key `c` (index 1); other keys are skipped; both are integers (slot `0x64e2580`); a missing field is 0; `a` at entry `+0x8`, `c` at entry `+0x10` |

So D is a map from a date key to `{a, c}`. Its own keys are values, not field names. The item keys are `a` and `c` only. No long-name key was found at any level.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_d_115.py --check
python3 -m unittest tests.test_user_value_d_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The ten `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: D is a map, not a struct

- `0x18d4f40` reads the marker byte. `0x80..0x8f` goes to `0x18d503e`, which calls `0x27a95f0` at `0x18d5075`. `0x90..0x9f` goes to `0x18d50ec`, which calls `0x28197a0` at `0x18d5123`. The marker table `0x4bdc60` sends `0xde` and `0xdf` to arms that read a 16- or 32-bit length and jump to the map path; `0xdc` and `0xdd` jump to the array path.
- The map visitor reserves `min(len, 0xaaaa)` entries of `0x18` bytes. For each entry it calls `0x17e3120` with `rdx = 0x459fd0` (`Date`) and `ecx = 4`, then `0x1be12b0`. It stores the key dword at `entry+0x0` and the 16-byte value at `entry+0x8` (`0x27a9669`, `0x27a9671`).
- The array visitor calls `0x1bd5ae0` for each element. That function calls `0x17e3120` with the same `Date` name (`0x1bd5c7b`) and then `0x1be12b0` (`0x1bd5cbd`). The array visitor stores the key dword at `+0x0` and the next 20 bytes at `+0x4` (padding and value).
- The struct visitor of #6239 matches field names. This map visitor has no field-name match at all: the only text it loads is `Date` and `duplicate key`.

## Evidence 2: the collector rejects repeated dates

- Both visitors end in `0x2dac950`. It sorts the entries (`0x26cb7a0` below `0x15` entries, else slot `0x64e85a8`), then compares each key dword with the next one (`mov edx,[rcx]; cmp edx,[rcx+0x18]`, `0x2dac999`). An equal pair returns tag `0x8000000000000001`, which both visitors turn into the 13-byte message `duplicate key`.
- Up to `0x40` entries: the result is built from `(cap, ptr, 0, len)` through `0x24d5580`. This matches the empty D default of #6239 (cap 0, ptr 8, 0, 0). Above `0x40`: tag `0x8000000000000000` and 24 bytes from `0x23b17f0`. The two builders are not read here.

## Evidence 3: the item value has the one-byte keys a and c

- `0x1be12b0` reads a map or an array. On the map path, a string key goes through the UTF-8 check (slot `0x64dfca8`); if its length is not 1, the key is index 2 (skip). A length-1 key gives index 0 for `a` and index 1 for `c` (`cmp al,0x63`, `cmp al,0x61` at `0x1be17d2` and `0x1be17db`). The byte-key path has the same guard (`cmp rdx,1`, `0x1be1866`) and the same compare (`0x1be1873`, `0x1be1878`).
- Index 0 reads an integer through slot `0x64e2580` into `[rsp+0xa0]` and sets `[rsp+0x90]`. Index 1 does the same into `[rsp+0x98]` and `[rsp+0x88]`. A second `a` or `c` gives `duplicate field` with the 1-byte name at `0x5c95b6` (`a`) or `0x5c9254` (`c`).
- At the end, a missing field is 0 (`cmove`, `0x1be1fac`). The result is tag 9, `a` at `+0x8`, `c` at `+0x10` (`0x1be1c71`, `0x1be1ca2`). The map visitor copies the 16 bytes from `+0x8` to the entry, so `a` is at entry `+0x8` and `c` at entry `+0x10`.
- The array path takes `a` from the first element and `c` from the second; a shorter array leaves the missing field at 0.

## Evidence 4: no long names

- No function in scope has a `pcmpeqb` constant compare (`66 0f 74 05`), which is how the p decoder matched its 16-byte names.
- The tool lists every RIP-relative `lea` target in the D decoder, the two visitors, the collector and the value decoder. Apart from jump tables and error objects, the only text targets are `Date`, `duplicate key`, `a` and `c`.
- In the value decoder, the only `cmp al, <letter>` instructions are the four key compares above.

## Implementation and comparison

The tool pins 40 instruction byte runs, decodes four marker-table entries and four joins, 9 direct calls and 2 slot calls, 6 string loads, the entry and value offsets, the collector limits and tags, and the `lea` / `pcmpeqb` / letter-compare censuses. Tests mutate bytes in a copy of the image and expect rejection (9 mutation tests). Where a mutation sits inside a pin, the test removes that pin so the derived check must catch it. Alternatives considered: decoding a crafted MessagePack value by running the code (not allowed for this repository); reading the two collection builders (bounded out).

## Results and limitations

- Result: D is a map from a `Date` key to `{a, c}`, sent as a map or as a list of pairs, with repeated dates rejected. The item keys are the one-byte `a` and `c`. Unlike p, D has no long-name key.
- Limits: the meaning of `a` and `c` is not claimed. The key decoder `0x17e3120` is read only for its name argument; its date format is not decoded. The two collection forms are named by their tags only.
- Next lead: the writer side of D in `0x3beac00`, to check whether it writes `a` and `c` in the same order and skips any default.
