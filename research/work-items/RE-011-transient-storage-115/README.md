# RE-011: reconstruct node #115 TLOAD/TSTORE handlers and the two-level transient map lookup

With this packet you can rebuild the EIP-1153 transient storage instructions of the node #115 EVM as runnable code. The
instructions are TLOAD `0x2994410`, TSTORE `0x2994e90` and the lookup `0x295f490` that TLOAD calls. The reconstruction
covers the fork gate, the static-call rule, the stack effects, and the exact two-level hash map: address → slot → value,
with both hashes, both probes and the zero results for empty tables. The tool proves the reconstruction against the real
machine code in 4,800 cases.

- Component ID: `evm` (task RE-011, EVM/forks: one bounded EVM adapter path)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference source is used.
- Claim status:
  - Observation: byte offsets, constants, call targets, opcode-table slots, and the agreement of the evaluated machine code
    with the model.
  - Inference: the names TLOAD/TSTORE/Cancun and the reading of `0x2972390` as the transient writer.
  - Unresolved: the body of the writer `0x2972390`.
- Scope:
  - Included: `0x2994410` (36 instructions), `0x2994e90` (39), `0x295f490` (132), their FDE extents, the two RELATIVE
    opcode-table slots, and the hash seed slot.
  - Excluded: the writer `0x2972390` (stubbed with its arguments recorded), the dispatcher that charges the static gas,
    and the code that clears the map at the end of a transaction.

## Reproduce

From the repository root, with Python 3 standard library only:

```
python3 tools/re11_transient_storage115.py --out research/work-items/RE-011-transient-storage-115
python3 -m unittest tests.test_re11_transient_storage115
sha256sum -c research/work-items/RE-011-transient-storage-115/MANIFEST.sha256
```

- The tool checks the input SHA-256 first.
- It reads sections, `.rela.dyn` and `.eh_frame` through `tools/elf_index.py` and `tools/fde_extents.py`.
- It never runs the binary or any external program.
- The tool exits non-zero on any mismatch or on any undetected control.
- Regeneration with a different `PYTHONHASHSEED`/`TZ` and a binutils-free `PATH` was byte-identical.
- The run takes about 6 s.

## Evidence

All addresses are virtual addresses in node #115. Every listed byte string is re-read from the file in
`constants.json` → `checked_bytes`.

### Dispatch

The RELATIVE opcode tables `0x64414b0` and `0x64421a0` are indexed from opcode `0x54`:

| Slot | Opcode | Target |
|---|---|---|
| `+0x0` | `0x54` | SLOAD `0x2993ff0` |
| `+0x40` | `0x5c` | `0x2994410` |
| `+0x48` | `0x5d` | `0x2994e90` |

See `constants.json` → `opcode_table_slots`.

### Handler `0x2994410` (opcode `0x5c`)

1. `cmp byte [rdi+0x1a9],0xb; jb` returns `0x2b`.
2. An empty stack (`[rdi+0x30]==0`) returns `0x2c`.
3. Otherwise the handler calls `0x295f490(out, host+0x360, interp+0x78, &top)` and writes the 32-byte result over the
   stack top. It returns 0.
4. No gas is touched in this body.

### Handler `0x2994e90` (opcode `0x5d`)

1. The spec gate is the same as TLOAD (`0x2b`).
2. `cmp byte [rdi+0x1a8],1; je` returns `0x28`. The test is equality with 1, so flag values 2 and 0xff pass. The cases
   cover both.
3. Fewer than two stack words returns `0x2c`, with the stack unchanged.
4. Otherwise the handler pops two words and calls `0x2972390(host+0x270, interp+0x78, &key, &value)`, where key is the
   old top and value is the word below it. It returns 0 whatever the writer returns.

### Lookup `0x295f490` (`out, map, addr, key`)

1. Outer header: ctrl `+0`, mask `+8`, items `+0x18`, secret `+0x20`. An item count of 0 writes zero.
2. Outer hash: `p = (a0 ^ secret) * (a1 ^ seed)`; `z = lo(p) ^ hi(p) ^ a2(u32)`; `h = fold(z * seed)`. Here `seed` is
   the word behind GOT `0x64dfa78` → `0x64ffe90` (NOBITS). The probe is SSE2 hashbrown with `h2 = h >> 57`.
3. Outer buckets are 0x40 bytes. The address is compared as 16 bytes plus a u32 lane.
4. The inner header sits in the outer bucket: ctrl `-0x28`, mask `-0x20`, items `-0x10`, secret `-0x08`. An item count
   of 0 writes zero.
5. Inner hash: `p = (k0 ^ isecret) * (k1 ^ seed)`; `z = lo ^ hi ^ k2`; `h = fold(z * (seed ^ k3))`. Inner buckets are
   0x40 bytes: a 32-byte key at `-0x40`, then the value at `-0x20`.
6. A miss at either level writes zero.

### Writer `0x2972390`

Its body is not evaluated, but the tool checks four of its instructions. They read ctrl/mask/items/secret at argument
`+0xf0/+0xf8/+0x108/+0x110`. With the argument `host+0x270`, this is the same header that TLOAD reads at `host+0x360`.

### Coverage

- Linear decode from the FDE extents: 36 + 39 + 132 instructions, all of them executed (`decoded-instructions.tsv`).
- `0x295f490` has no calls. `0x2994410` calls only `0x295f490`, and `0x2994e90` calls only `0x2972390`. There are no
  indirect calls.

Excerpt for readers (objdump, not part of the generated evidence):

```
2994e99: 80 bf a8 01 00 00 01   cmp  BYTE PTR [rdi+0x1a8],0x1
2994ea0: 74 79                  je   2994f1b          ; mov al,0x28
295f5a5: 4c 33 49 18            xor  r9,QWORD PTR [rcx+0x18]   ; seed ^ key limb 3
295f5a9: 49 f7 e1               mul  r9
```

## Implementation and comparison

The reconstruction is `model()`, `tload_value()`, `addr_hash()` and `key_hash()` in
`tools/re11_transient_storage115.py`. It is a pure-Python implementation. No Rust implementation exists yet.

### How the cases are built

- 4,800 deterministic cases (SHA-512 stream; about three quarters TLOAD, one quarter TSTORE).
- The tool lays out real hashbrown tables (ctrl bytes, mirrored tail group, buckets) for both levels with the
  reconstructed hashes.
- It then evaluates the original machine code with a concrete x86-64 evaluator. The evaluator covers integer ops, mul,
  tzcnt and the SSE2 forms on this path.
- The cases cover:
  - decoys with the target's h2 but one flipped key bit;
  - near keys that differ in exactly one 64-bit limb;
  - near addresses, including the u32 lane;
  - tombstones and crowded first groups that force a later probe group;
  - empty outer and empty inner tables that still hold the key;
  - the fork gate, underflow, and static values 0/1/2/0xff.

### What each case compares

- result byte;
- stack length and top;
- the writer's arguments (pointer, address, key, value);
- callee-saved registers and `rsp`;
- every other byte of the interpreter, host, tables and stack.

### Result

- 4,800/4,800 match.
- Executed instructions: 207/207.
- Outcome classes are in `outcome-classes.tsv`. Every class has at least 101 cases.

### Negative controls (`negative-controls.tsv`)

27/27 were detected:

- 10 model mutants, including a wrong address hash without the secret and a wrong key hash without limb 3. The table is
  then laid out with the wrong hash, so the real probe misses.
- 15 one-byte code mutants: thresholds, offsets, h2 shifts, the limb index, the value offset and result codes.
- 2 input controls: a flipped `.text` byte fails the digest, and an address past `.text` is rejected.

## Results and limitations

- Results: `summary.json` records 4,800 cases, 0 mismatches, 207/207 instructions, 27/27 controls. Unit tests: 11 OK, 0
  skips.
- Known limits:
  - The seed word is NOBITS, so the tool supplies it.
  - The writer is stubbed. Its insert, journaling and allocation paths are not covered, and neither is the code that
    clears the map between transactions.
  - Spec byte 0x0b is read here as Cancun; that is an inference from EIP-1153, not from the bytes.
  - The static gas of 100 for these opcodes is charged outside these bodies and is not checked here.
- No PROGRESS gate is requested.

Next question: does the writer `0x2972390` record a journal entry, at `host+0x270` below `+0xf0`, with the previous
value, so that a revert restores transient slots? And where is the map at `host+0x360` cleared?
