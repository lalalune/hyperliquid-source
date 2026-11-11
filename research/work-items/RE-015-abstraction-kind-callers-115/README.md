# RE-015: direct callers of node #115 abstraction-kind visitors

- Component: `constants`; bounded RE-015 caller census.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred source was read or copied.
- Claim status: **observation** — direct `E8 rel32` call sites to five visitor entries, raw call bytes, and the unique containing FDE range per site. **Unresolved** — source-level caller names, struct fields, action identity, indirect calls, and tail calls.
- Bounded question: where do the five previously reconstructed abstraction-kind visitor copies have direct callers in node #115, and which FDE contains each call?
- Scope: the file-backed `.text` section and the five exact visitor targets listed below. This is not a complete call graph or caller-source attribution.

## Reproduce

From the repository root, with Python 3.10+ and the pinned artifact materialized:

```sh
python3 tools/re015_abstraction_kind_callers_115.py --out research/work-items/RE-015-abstraction-kind-callers-115
python3 -m unittest tests.test_re015_abstraction_kind_callers_115
python3 research/work-items/RE-015-abstraction-kind-callers-115/verify.py
```

Observed tools: Python 3.14.3 and GNU objdump 2.47.20260726. To independently confirm the seven direct-call instruction sites:

```sh
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x1c0ef86 --stop-address=0x1c0ef8b artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x3164176 --stop-address=0x316417b artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x48d2956 --stop-address=0x48d295b artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x1debabf --stop-address=0x1debac4 artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x1e22089 --stop-address=0x1e2208e artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x3f7f8cf --stop-address=0x3f7f8d4 artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x3fbb239 --stop-address=0x3fbb23e artifacts/node/115/hl-node
```

The producer authenticates the complete target digest, scans all of `.text` for `E8 rel32` destinations matching the five entries, and records exact call bytes and FDE ranges. It executes no captured code and makes no network request. Output is deterministic. To check decoded instruction boundaries over the whole file-backed `.text` section, the following full-section disassembly returns exactly the seven sites listed below (GNU objdump 2.47.20260726):

```sh
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --section=.text artifacts/node/115/hl-node | rg -i 'call[q]?\s+.*(23c65f0|3bdd720|4d6b5d0|23c6720|3bdd5e0)(\s|$)'
```

The byte scan is exhaustive for direct near calls encoded as `E8 rel32`; the disassembly independently confirms that every matching site decodes as a call instruction. Neither method counts indirect calls or tail jumps.

## Evidence and results

All addresses are original ELF virtual addresses.

| Visitor entry | Direct call sites | Containing FDE range(s) |
| --- | --- | --- |
| `0x23c65f0` | `0x1c0ef86` | `0x1c0eab0..0x1c0f199` |
| `0x3bdd720` | `0x3164176` | `0x3163ca0..0x3164389` |
| `0x4d6b5d0` | `0x48d2956` | `0x48d2480..0x48d2b69` |
| `0x23c6720` | `0x1debabf`, `0x1e22089` | `0x1deba10..0x1debb91`, `0x1e21fc0..0x1e220e3` |
| `0x3bdd5e0` | `0x3f7f8cf`, `0x3fbb239` | `0x3f7f820..0x3f7f9a1`, `0x3fbb170..0x3fbb293` |

The complete scan finds seven direct calls: one each to three tagged-word visitor copies and two each to the two `Result<u8, E>` visitor copies. Each site lies in exactly one recorded FDE. The prior RE-015 codec packet establishes these as five separately reconstructed visitor bodies; this packet adds the first direct caller locations. No source field or enclosing type is inferred from FDE ranges alone.

No Rust implementation or component gate is claimed. No progress gate is requested. Next question: inspect the seven caller bodies for shared register arguments and any directly adjacent field-key evidence, without assigning source names until independently supported.
