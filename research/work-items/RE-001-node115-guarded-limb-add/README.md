# RE-001: guarded four-limb addition

- Component: unassigned node code; function map for the node reconstruction. Ownership is unresolved.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No reference source is used. This is independently authored static analysis under the repository's MIT terms.
- Question: what does the complete body at `0x298f5b0` compute on its success and short-input paths?

For a valid descriptor at RDI, let `n` be its unsigned qword at offset `0x30`, and let the qword at `0x28` point to consecutive 32-byte entries. If `n < 2`, the function leaves the descriptor and entry buffer untouched and returns `0x2c` in RAX. Otherwise, it decrements `n`, loads the former last entry, adds its four little-endian 64-bit limbs to the preceding entry using carry propagation, stores the low 256 bits back to the preceding entry, and returns zero. The final carry is discarded. The former last entry is not explicitly modified. The input must provide valid readable/writable, non-overlapping descriptor and entry storage, with address arithmetic and stack/return state valid. Faults, concurrent mutation and aliasing are outside this statement.

## Evidence and instruction walk

All addresses are original ELF virtual addresses; the body begins at file offset `0x298e5b0`. Its half-open range is `0x298f5b0..0x298f5f9`; SHA-256 `272d95480ebd94fb1aadb38d2f0a3eb1ba4d041b26947a919af5e0cc1d36061f`. The FDE is at VA and file offset `0xd732d0`, with CIE at VA and file offset `0xca6ed8` (`zR`, no LSDA). The raw FDE is `10000000fcc30c00d8c2c1014900000000000000`; the raw CIE is `1400000000000000017a5200017810011b0c070890010000`. Following the FDE endpoint are `cc` alignment bytes up to the next FDE start at `0x298f600`. The endpoint is corroborated by the entire decoded control flow, including both returns; an FDE by itself is not proof of a function boundary.

The complete unnormalized bytes and instruction-by-instruction walk are in `records.json`; the pure Python decoder accepts only the stated forms and checks the branch target and complete coverage. In order: load `n`, compare unsigned against 2 and branch below to the short-input return; load the base, decrement `n`, multiply the index by 32 via a shift, load all limbs of the last entry, and store the decremented count. `ADD` updates the low preceding limb; three `ADC` instructions update the remaining limbs with incoming carry. `XOR EAX,EAX; RET` yields zero. The short path `MOV AL,0x2c; RET` yields RAX `0x2c` because the preceding load and unsigned comparison constrain its old value to 0 or 1. Stores occur in the stated order; no atomicity is claimed.

The full-body decoder finds no calls or tail transfers, so there are no callee identities or extents to resolve. The `e8`/`e9` rel32 census scans every byte position of the complete `.text` interval `[0x1419300,0x63f0a00)`. It produces the count below; because this scan includes unaligned bytes it is a conservative candidate census, not a proof of instruction boundaries. The dynamic relocation section contains `R_X86_64_RELATIVE` entries at file offsets `0x61068` and `0x62df0`, with slots `0x6441218` and `0x6441f08`, respectively, and addend `0x298f5b0`. These are possible indirect references, not identified callers or proof of runtime reachability. All referenced counts below come from `records.json` and are checked against this table by the tests.

| JSON count | Value |
| --- | ---: |
| instruction_count | 20 |
| body_bytes | 73 |
| padding_bytes | 7 |
| callee_count | 0 |
| caller_count | 0 |
| entry_relocation_count | 2 |
| adc_count | 3 |

The return and arithmetic follow directly from the instruction bytes. In particular, the `ADC` chain is equivalent to addition modulo `2^256` for the four limbs, independent of discarded carry. No original symbol, Rust type, ownership, semantic role, calling convention beyond the stated register/memory observation, or protocol association is inferred. The indirect consumers, relocation-table meaning, exception behavior and full node implementation remain unclosed. No reconstruction or progress gate is claimed.

## Novelty check

Before creating this packet, both commands below returned no matches; the function has no callees whose behavior is additionally bound. The check covered the retained research tree and the three supplied adjacent PR title lists:

```sh
rg -i '298f5b0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '43578800' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The new packet itself naturally matches these queries after creation. The title-list check cannot establish the contents of unlisted or unpublished work.

## Reproduction and limits

From the repository root, Python 3.10 or newer and the authenticated target are required. The retained run used Python 3.13.5; GNU objdump 2.44 was used for exploratory inspection only, never by the producer, verifier or tests. The producer checks the entire target digest before reading semantic evidence or creating output, derives the JSON from the binary, copies the authored README and verifier, and recomputes the manifest. The record has no normalized byte masks. The independent value model is a mathematical projection, not target execution.

```sh
python3 tools/node115_guarded_limb_add.py --out research/work-items/RE-001-node115-guarded-limb-add/
python3 -m unittest tests.test_node115_guarded_limb_add -v
python3 research/work-items/RE-001-node115-guarded-limb-add/verify.py
make verify
make catalogue-check
```

Tests cover count boundaries, carry propagation across each limb and overflow, wrong target digest, body mutation, shifted FDE, branch retarget, an inserted call opcode, relocation mutation and padding mutation. There is no actual callee to redirect; inserting a call is rejected by the full-body decoder. Public generation rejects a wrong input before output creation. No node or visor execution, network, keys, chain action, external fixture, source build or binary-equivalence comparison was performed. Next, trace the two relocation slots to their consumers and recover the surrounding object and component identity before assigning application meaning.
