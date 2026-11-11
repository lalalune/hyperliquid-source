# RE-011: transient storage writer's change journal

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for the RE-011 EVM adapter work and [issue #3918](https://github.com/lalalune/hyperliquid-source/issues/3918). The [TLOAD/TSTORE packet](../RE-011-transient-storage-115/README.md) maps the TSTORE caller and transient lookup but leaves writer `0x2972390` outside its implementation. This packet follows selected writer mutation and journal paths. It does not reconstruct the full map, journal consumer or EVM execution.

At `0x2994ef0..0x2994f0c`, the already mapped TSTORE success arm passes `host+0x270`, a 20-byte address pointer, a 32-byte key pointer and a 32-byte new-value pointer to `0x2972390`. The writer first tests all 32 new-value bytes for zero. Its two branches have different map behavior:

- On a **nonzero** input, the selected existing-key path at `0x2972812` saves the old 32-byte value, writes the new 32 bytes in its place, and compares the saved and new bytes at `0x29728e4`. Equality branches directly to the epilogue without a new journal entry. On the selected insertion path, the writer installs the supplied key/value and initializes the saved old value to 32 zero bytes before the same comparison.
- On a **zero** input, an empty outer table returns immediately. A selected inner-key miss also returns. On a selected inner-key hit, the writer updates the control bytes and count, loads the removed value, and jumps directly to the journal construction at `0x2972916`. That jump bypasses the later equality comparison; the claim does not assume that malformed or zero-valued existing rows are impossible.

On the selected change/removal route, the vector-like header uses `arg1+0x18` for capacity, `+0x20` for data and `+0x28` for length. When length equals capacity, call `0x2972950` reaches relocation slot `0x64e6cf0` → `0x43bc980`; this packet assumes that helper returns normally with sufficient space. It then appends a record at `data + length*0x58` and publishes `length+1`:

| Offset | Selected stores |
| --- | --- |
| `+0x00` | tag byte `0x0a` |
| `+0x01..+0x14` | 20 bytes from the address argument |
| `+0x18..+0x37` | 32 bytes from the key argument |
| `+0x38..+0x57` | saved 32-byte previous value |

The actual vectorized key stores also write three bytes at `+0x15..+0x17`; their values are not characterized here. Existing entries, zero-input removal, and nonzero insertions are distinct selected paths; hash probing, full allocation behavior, unwinding, journal replay/revert, transaction clearing, concrete runtime reachability and protocol correctness remain open. The observations assume valid nonaliasing arguments and map metadata, normal helper returns and adequate capacity. They are not a claim of target execution or reconstructed whole-node behavior.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-011-node115-transient-journal/verify.py
```

The static verifier checks the target digest, both complete indexed FDEs and decoded partitions (511 and 39 instructions), 180 selected instruction spans, 72 explicit instruction pins, eight selected edges, the growth-helper relocation and six corruption controls. Capstone 5.0.7 is required. No target instructions are executed or emulated. The prior opcode handler and lookup evidence is credited to the earlier packet; no component gate is advanced.
