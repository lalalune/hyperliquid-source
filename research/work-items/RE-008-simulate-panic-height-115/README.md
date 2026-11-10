# RE-008: node #115 simulate-panic stop checks and the writers of their fields (86th stage)

- Component ID: abci. Question: #6090 found that the begin functions `0x5483850` (layout A) and `0x5483f50` (layout B) panic with `explicit panic` at `l1/src/simulate_panic.rs:10:13` when a byte (A `+0x39b0`, B `+0x4520`) is set, the new height equals a stored height (A `+0x39a8`, B `+0x4518`) and box byte `+0xb9a` (B `+0x170a`) is not 3. This stage asks where else that check runs and what writes its fields.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #5970 and #6090.
- Claim status: instruction bytes, offsets, strings, the Location record and the reference and store censuses are observations. "Stop", "selector", "clone", "Option tag" and "None niche" are inferred labels. The binary was not executed.
- Scope included: the six check sites, their panic loads, all non-stack stores to the four stop offsets and to the selector byte, and the immediate compares of the selector. Scope excluded: the meaning of the selector values, the bodies of the functions that hold the value-2 stores, and any whole-struct copy that fills the fields (deserialisation or construction).

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/simulate_panic_height_115.py --check
python3 -m unittest tests.test_simulate_panic_height_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: six check sites

The Location `0x6492ef0` (`l1/src/simulate_panic.rs:10:13`) is loaded by exactly six RIP-relative `lea` instructions in `.text`, each next to `"explicit panic"` (`0x7db393`, `mov esi, 0xe`) and the panic slot `0x64df730`:

| Function | Role | Byte test |
|---|---|---|
| `0x5483850` | begin, layout A (#6090) | `test byte [+0x39b0], 1` (`0x5483903`) |
| `0x5483f50` | begin, layout B (#6090) | `test byte [+0x4520], 1` (`0x5484003`) |
| `0x2bdf270` | layout-A function | `test byte [+0x39b0], 1` (`0x2bdf30d`) |
| `0x54897e0` | quorum entries, layout A (#6046) | `cmp byte [+0x39b0], 0` (`0x548bfc9`) |
| `0x5486720` | quorum entries, layout B (#6046) | `cmp byte [+0x4520], 0` (`0x5488ed4`) |
| `0x2c71eb0` | layout-A function | `cmp byte [+0x39b0], 0` (`0x2c7444e`) |

In all six, the panic also needs the height (`+0x28`) to equal the stored height (A `+0x39a8`, B `+0x4518`) and the selector byte (A `+0xb9a`, B `+0x170a`) not to be 3. Three sites panic when bit 0 of the byte is set; three panic when the byte is 0. The two polarities are pinned; which value means "armed" is not resolved here.

## Evidence 2: who writes the stop fields

A store census over `.text` (`mov`/`movb` with a 32-bit displacement, with or without SIB, any base except `rsp`/`rbp`):

| Offset | Stores |
|---|---|
| A `+0x39a8` (height) | `0x55f27c2` |
| A `+0x39b0` (byte) | `0x55f27d1`, `0x2addc04`, `0x2cc1ced`, `0x3c1296f` |
| B `+0x4518`, `+0x4520` | none |

- `0x55f27c2`/`0x55f27d1` are in `0x55ea030`, which loads both fields from another value (`0x55f1ce3`, `0x55f1cf2`) and stores them unchanged: a clone.
- `0x2addc04` (in `0x2adce40`), `0x2cc1ced` (in `0x2cc1120`) and `0x3c1296f` (in `0x3c12800`) store the value 2 to the byte. Inference: 2 is not a valid tag or bool value, so these mark an outer `Option` as `None` through the byte's niche.
- Inference: no code in `.text` sets a stop height or arms the byte field by field. The fields reach a state value only through whole-value copies, such as deserialisation or construction, which are not mapped here. Layout B has no store at all, which fits B being built by copying A (#6006).
- Nothing clears the fields after a panic fires; the panic ends the step.

## Evidence 3: the selector byte

- `+0xb9a` has one non-stack store, `0x2fc32ad` in `0x2fc21d0`, which copies a stack byte next to the stores of `+0xb90`, `+0xb98` and `+0xb99` (inference: a construction or deserialisation step).
- Immediate compares of the byte use only 2 and 3: A `+0xb9a` 12 × 2 and 43 × 3; B `+0x170a` 9 × 2 and 21 × 3.
- What the values mean is not mapped. #6067 found that startup compares this byte with poller state `+0x556`.

## Implementation and comparison

The tool pins 42 byte runs, 17 RIP-relative references, the Location record and the message, and recomputes the Location census, the store census and the selector compare census. Tests mutate one byte in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: the simulate-panic stop runs in six functions across both layouts and the catch-up path; its height and flag are written only by a clone and by `None`-niche stores; the selector byte is written once.
- Limits: the census does not see stores through a computed address, `rep movs`/`memcpy` copies or stack-built values (stack stores at `0x199e478`, `0x32cc588`, `0x49dba38` are not followed). The two byte-test polarities, the meaning of selector values 2 and 3, the roles of `0x2bdf270` and `0x2c71eb0`, and the functions holding the value-2 stores are not mapped. A string `crash_height` (`0x93bcb4`) is referenced once, at `0x5a8b1b3`, as a name passed with runner `+0x140` to `0x4f0e990`; it is not tied to these fields.
- Next lead: the deserialiser or constructor that fills A `+0x39a8`/`+0x39b0`, starting from the stack builders above.
