# RE-021: caller account gates and deduction write-back in both node #115 transaction drivers

This packet adds an executable Python reconstruction of the caller-side step that both node #115 transaction drivers run around the payer balance helper `0x2973440`. It covers the code gate, the nonce gate with its three rejection values, the payer handoff, the touched flag, the journal entries with tags 2, 3 and 6 (including the exact 0x58-byte entry bytes), the balance store and the saturating nonce bump. The reconstruction matches the real machine code of both drivers in all 3,992 cases. A Rust port of the transaction preflight can therefore implement "validate the caller against its account, then deduct" from this model, and the journal rollback can rely on the byte layout of the three entry kinds recorded here.

- Component ID: `evm` (task RE-021, address-09 transaction path; connected to RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `05bc2de30`. `references/can1357-hl` was not used. No node #94 result is reused.
- Claim status: observation (byte-level equality of the reconstruction with the evaluated machine code on every listed case). Names such as "nonce too high" and "call kind" are labelled inferences below.
- Scope included and excluded:
  - Included: driver A fragment `0x29a1ce0..0x29a1fa4` in the FDE `0x29a1290..0x29a5fca`, and driver B fragment `0x29634ef..0x2963796` in the FDE `0x2962aa0..0x296754d`. Each fragment includes its gate blocks and rejection blocks (A: 159 instructions, B: 154). Every instruction in both fragments is executed by at least one case.
  - Excluded:
    - The payer helper `0x2973440` is replaced by a stub with fixed results. Its own reconstruction is a separate pending draft.
    - The account load wrapper `0x299f4d0` (A) and the auxiliary call `0x299f1c0` (B) that precede the fragments are not evaluated.
    - The default-bytecode branch (`0x29a26b2` / `0x2963e59`: lazy static, atomic reference count) is not evaluated.
    - The vector growth routine `0x43bc980`, called through the slot `0x64e6cf0`, is not evaluated.
    - Everything after the exits is not evaluated.

## Reproduce

From the repository root, with Python 3 and the standard library only (no binutils are needed, and the binary is never executed):

```
python3 tools/re21_caller_deduct115.py --out research/work-items/RE-021-caller-deduct-115
python3 -m unittest tests.test_re21_caller_deduct115
sha256sum -c research/work-items/RE-021-caller-deduct-115/MANIFEST.sha256
```

The tool checks the input SHA-256 first and stops on any other digest. It reads the sections through `tools/elf_index.py` and the FDE extents through `tools/fde_extents.py`. Code bytes are decoded by a fixed-form decoder that raises on any form it does not know. The evaluator runs the fragments over synthetic account, code, journal and frame memory. Two generations with different `PYTHONHASHSEED`/`TZ` and with `PATH` lacking binutils produced byte-identical files. A run takes about 10 s.

## Evidence

All addresses are virtual addresses in `.text` of node #115. The tool re-reads from the ELF bytes the FDE extents, call edges, growth slot relocation, journal tag immediates and the use of every frame offset, and writes them to `constants.json`. It fails if any of these differs. Rejection values and branch targets below are covered by the evaluated cases and the code mutants.

### Fragment map

| Step | Driver A | Driver B | Observation |
| --- | --- | --- | --- |
| Inputs | `0x29a1ce0` reads the wrapper output at frame +`0x230`: account at +0, journal at +8, address at +`0x24..+0x37` (copied to frame +`0x64`) | registers r13 = account, r12 = journal, rbp = tx; address at frame +`0xd4` | the same 20 address bytes go into every journal entry at +1 |
| Code gate (unless byte frame +`0xd73` / +`0x1253` is set) | `0x29a20a0` | `0x2963865` | account +`0x70` is null → default-bytecode branch; else if code +`0x50` ≠ 0 and byte code +`0x7c` = 0 → rejection 5 |
| Nonce gate (unless byte +`0xd71` / +`0x1251` is set) | `0x29a20c8` | `0x296388c` | `(tx & state) == 2^64-1` → 8; `seta` / `sbb $0,%al`: tx > state → 9, tx < state → 10 |
| Payer handoff | `call 0x2973440` at `0x29a1d84` | at `0x2963553` | argument is a 32-byte copy of account +`0x28`; result word ≠ `0x21` → exit with that word |
| Touch | `0x29a1ddd` | `0x29635ad` | if bit 2 of account +`0x8c` is clear: set it, push entry tag 2 |
| Balance change | `0x29a1e2d` (`pcmpeqb`/`pmovmskb == 0xffff`) | `0x2963608` | if new ≠ old: push entry tag 3 carrying the old balance, then store the new balance at account +`0x28` |
| Nonce bump (if byte +`0xcec` / +`0x11cc` == 1) | `0x29a1efa` | `0x29636dc` | touch again; if account +`0x68` ≠ 2^64-1: increment it and push entry tag 6; at 2^64-1 nothing is written |
| Journal push | four `call *0x64e6cf0` sites per driver | same | growth is called only when len == cap (vector at journal +0 cap, +8 ptr, +0x10 len; `imul $0x58`) |

### Exits

| Exit | Driver A | Driver B |
| --- | --- | --- |
| Continue | `0x29a1fa4` (next call `0x2668560`) | `0x2963796` (next call `0x2668a20`) |
| Rejections | 5/8 → `0x29a276d`, 9/10 → `0x29a2777`, value in eax | all at `0x2963ee0`, value in ebx |
| Payer result ≠ `0x21` | `0x29a2106`, word in rax | `0x2963ee0`, word in rbx (reached via `0x29638c0`) |
| Default-bytecode branch | `0x29a26b2` (boundary) | `0x2963e59` (boundary) |

### Entry bytes

Each 0x58-byte journal entry has the following layout, observed in every case:

- `+0`: the tag.
- `+1..+0x15`: the address.
- Tag 3 only: a 36-byte copy starts three bytes before the old balance. Bytes `+0x15..+0x18` are therefore the low bytes of the helper result word still in the frame (`21 00 00`), and `+0x18..+0x38` hold the old balance (32 bytes, little-endian).
- Tags 2 and 6: nothing is written after `+0x15`.

### Order and structure

- The code gate runs before the nonce gate, and both run before the payer.
- A rejection or a payer error leaves the account, flags and journal unchanged.
- Both drivers have the same structure. They differ only in registers, frame offsets and exit layout.

## Implementation and comparison

There is no Rust implementation yet. The executable Python reconstruction is `model()` in `tools/re21_caller_deduct115.py`. `expected()` turns its result into exit address, exit value, payer call count and argument, journal length, the exact appended entry bytes, the final balance, nonce and flags, the number of growth calls, and the integrity of the entries that already existed.

For each case, the evaluator runs the real fragment from its entry until one of its exits, with these stubs:

- The payer stub checks all four argument registers, records the balance it was given, writes the chosen result and clobbers the caller-saved registers.
- The growth stub accepts only the journal vector at len == cap and reallocates it.

Cases (`cases.tsv`, 1,996 per driver):

- 1,200 grid cases: skip-code {0,1} × code {absent, len 0, len 0 delegated, len 33, len 33 delegated} × skip-nonce {0,1} × 10 nonce pairs (including 2^64-1, 2^64-2 and 2^63 neighbours) × payer {same balance, other balance, zero, error 6, 7, 0x12}.
- 96 direct entries at the nonce bump block, with flag bit 2 clear in half of them. These make the second touch reachable, because from the fragment entry the first touch has always set bit 2.
- 700 random cases.

Flags, kind {0,1,2}, journal capacity {0,1,2,3,4,8} and length come from a SHA-512 stream with a fixed label.

`negative-controls.tsv` lists 21 controls:

- 11 model mutants. Each is detected:
  - rejection 9/10 swapped;
  - the 8 rejection dropped;
  - delegation ignored;
  - nonce gate first;
  - skip bytes swapped;
  - touch always pushing;
  - balance entry always;
  - new balance in the entry;
  - bump on any non-zero kind;
  - bump wrapping;
  - no growth.
- 8 single-byte code mutants. Each changes the real fragment and is detected: tag 3 → 4, kind compare 1 → 2, touched test 4 → 8, code 9 → 11, tag 6 → 7, saturation compare −1 → −2, equality mask `0xffff` → `0xfffe`, code 5 → 6.
- 2 input controls, both rejected: a flipped `.text` byte (digest) and an address past `.text`.

## Results and limitations

- `summary.json`:
  - Driver A: 1,996 cases, 0 mismatches, 159/159 instructions executed.
  - Driver B: 1,996 cases, 0 mismatches, 154/154 instructions executed.
  - Negative controls: 21/21 detected.
  - Outcome classes: 32 (`outcome-classes.tsv`).
  - Unit tests: 7.
- Observed edge (A and B): when the nonce gate is skipped and the account nonce is 2^64-1, a call-kind transaction passes and the nonce stays 2^64-1, with no tag 6 entry. With the gate enabled, the same state is rejected with 8 only when the transaction nonce is also 2^64-1. This is a static observation about the fragment, not a claim about reachable chain state.
- Inferences:
  - 5/8/9/10 correspond to rejecting a caller with code, nonce overflow, nonce too high and nonce too low.
  - Kind byte 1 means a call (non-create) transaction.
  - Entry tags 2/3/6 are account touched, balance change and nonce change.
  - The layout and behaviour of each item above is observed; only these names are inferred.
- Limits:
  - The payer helper, the account load wrapper, the auxiliary call in B, the default-bytecode branch and the growth routine are stubs or boundaries, as listed in Scope.
  - The growth stub's doubling policy is the harness's own. Only "called exactly when len == cap" and the preserved existing entries are checked against the code.
  - Frame and account offsets are verified to appear in the code's displacements, not traced back to their producers.
- No progress gate is requested. This covers one preflight step, not the `evm` component's mapped, built, behavior or identity gate.
- Next question: which exits at `0x29a1fa4` / `0x2963796` consume the result of `0x2668560` / `0x2668a20` (status `0x25`, byte +`0xd01` == 4), and does that function read the journal entries written here?
