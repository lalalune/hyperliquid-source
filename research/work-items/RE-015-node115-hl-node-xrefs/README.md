# RE-015: static code references to the node115 `hl-node` bytes

- Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Task: RE-015, bounded static data-reference follow-up to the literal inventory in PR #2338.
- Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Captured code executed: no. The target is hashed and read only.

## Finding

The byte token `hl-node` occurs five times in `.rodata`. GNU `objdump -d -w`
over the full `.text` maps those occurrences to four kinds of direct reference:

| Token VA | Direct reference evidence | Static observation |
| --- | --- | --- |
| `0x434a3e` | `0x2ae624e`, `0x2ae62e3`, `0x2ce02d6`, `0x2ce037b` target `0x434a2d` | The token is 16 bytes into the text following a `0x1e` prefix. Two sites store the parent pointer in stack records; two pass it to indirect formatter calls. |
| `0x440f36` | `0x15a230b` targets `0x440f30` | The target is six bytes before the token in the same encoded data region. The instruction forms that base pointer and passes it to an indirect call. |
| `0x605ccd` | `0x2ae4574`, `0x2aeb181` target the token | Both form a pointer to the token. At `0x2ae457b` and `0x2aeb18f`, the caller stores length 7 beside the pointer. |
| `0x60f0b2` | `0x2cb6791`, `0x2cde639` target the token | Both form a pointer to the token; the following stores pair it with length 7. |
| `0x92a890` | `0x2ae429b`, `0x2ae42a4`, `0x2b7b663`, `0x2b7b66c` read `0x92a893` / `0x92a890` | Each pair loads overlapping four-byte pieces (`hl-n` and `node`) into a new buffer and records length 7. |

These are byte and instruction relationships, not claims about the original
source-level variable names or runtime meaning. For `0x434a3e` and `0x440f36`,
the code refers to the containing data at its base, not to the interior token
address itself. No data-only, computed, or indirect pointer census is claimed.

## Reproduction

With GNU binutils `objdump` available on `PATH`:

```sh
python3 research/work-items/RE-015-node115-hl-node-xrefs/verify.py
python3 -m unittest tests.test_foundation_hl_node_xrefs -v
```

The verifier checks the artifact digest, all five occurrence addresses, each
expected direct disassembly reference, and the exact instruction bytes. It
streams disassembly output and never executes the captured program. `records.json`
contains the machine-readable result and byte evidence.

## Recorded verification

On macOS arm64 with Python 3.14.3 and GNU objdump 2.47.20260726:

- `verify.py`: `verified occurrences=5 direct_references=13`.
- Focused unittest: 1 passed.
- `make doctor`: analysis tools available; exact rebuild remains unready for
  the repository's documented missing provenance and integration evidence.
- `make verify`: artifacts, pinned submodules, and all 2,145 evidence-packet
  manifests passed.
- `make reproduce`: node and visor inventories reproduced.
- `make catalogue-check`: passed.
- Full `make test` did not complete. Existing
  `test_grow_family_panic_static.py` called the native differential path and
  failed at `span mmap failed` before code execution on this host. The suite
  was interrupted before completion; the separate opt-in gate in PR #5128 is
  not yet merged. No captured code was executed.

## Limits

The scan covers objdump's direct resolved references in `.text` to the listed
data anchors only. It does not identify indirect references through tables,
infer source ownership, establish runtime reachability, or make a reconstruction
completion claim. Existing RE-015 and component gates remain unchanged.
