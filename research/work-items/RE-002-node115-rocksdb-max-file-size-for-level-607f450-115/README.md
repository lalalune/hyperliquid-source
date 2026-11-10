# RE-002: rocksdb MaxFileSizeForLevel 0x607f450 (node #115)

Task: RE-002 (build provenance / dependency window). Bounded question:
what does the 58-byte leaf routine at 0x607f450 return for an options
struct pointer, a level, a compaction style, a base level and a flag, and
what do its callers depend on?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). Vendor census member
`d7ece8bd5f9dc186-cf_options.o`, rlib
`liblibrocksdb_sys-b032f986857674dc.rlib`, crate `librocksdb-sys`,
candidate version `0.11.0+8.1.1`, symbol
`_ZN7rocksdb19MaxFileSizeForLevelERKNS_16MutableCFOptionsEiNS_15CompactionStyleEib`
(`rocksdb::MaxFileSizeForLevel(MutableCFOptions const&, int,
CompactionStyle, int, bool)`), `native` true.

## Answer

The routine selects a configured max file size out of the level-indexed
table the options struct points at. It is a leaf: it calls nothing,
allocates nothing, stores nothing, and reads exactly one table entry.

Argument registers, read off the disassembly: `rdi` = options,
`esi` = level, `edx` = style, `ecx` = base, `r8b` = flag. The only field
read from options is `options + 0x1e0`, a table pointer.

  idx = level
  if level >= base and (style & 0xff) == 0 and (flag & 0xff) == 1:
      idx = level - base            # 32-bit subtraction, sign-extended
  **result = table[idx]**,  table = *(uint64_t **)(options + 0x1e0)

Behaviour, pinned from the disassembly:

1. **The level/base compare.** `cmp %ecx,%esi` / `setl %al`
   (0x607f457, 0x607f462) record `level < base` in `al` (signed).
2. **The style test is on the low byte only.** `mov %edx,%edi`
   (0x607f459) moves the style into `dil`, then `test %dil,%dil` /
   `setne %dil` (0x607f465, 0x607f468) test and record only
   `style & 0xff`. A style of 256 passes the test as *zero* and takes the
   subtraction path.
3. **The two conditions combine with `or`.** `or %dil,%al` /
   `jne 0x607f477` (0x607f46c, 0x607f46f): the plain level index is used
   when `level < base` or `(style & 0xff) != 0`.
4. **The flag test is on the low byte only.** `cmp $0x1,%r8b`
   (0x607f471) compares only `flag & 0xff` against 1; `je 0x607f480`
   (0x607f475). A flag of 257 behaves like 1 and 256 like 0.
5. **The index.** `movslq %esi,%rsi` (0x607f477, and 0x607f482 on the
   subtraction path) sign-extends the index, which is computed as
   `sub %ecx,%esi` (0x607f480) when the flag path is taken. That
   subtraction is only reachable when `level >= base`, so the index is
   never negative.
6. **One table read.** `mov (%rdx,%rsi,8),%rax` (0x607f47a, and
   0x607f485 on the subtraction path), a 64-bit entry with an 8-byte
   step. There is **no bound check**: the routine trusts the caller's
   table, which is why the model takes the table as an input and rejects
   an index outside it instead of guessing.

### What the disassembly pins that the source does not spell out

The low-byte tests in (2) and (4) and the sign-extended 32-bit index in
(5) are properties of *this build's* code generation. They are the cells
the model's `style` and `base` case families exercise directly: a model
written as `style != 0` or `flag != 0`, or with a 64-bit index, would
return a different entry for `style = 256`, `flag = 256` or `flag = 257`.

## Consumers: what the callers depend on

Census (executable-LOAD-segment E8/E9 scan, rel32 resolved, each
candidate Capstone-validated at the instruction boundary by linear
disassembly from its enclosing FDE start; reproduced by census.py and
re-run inside verify.py): **10 direct calls, 0 tail jumps, 10 distinct
caller FDEs**, no stored qwords and no relocations.

`caller_use.tsv` records, for every call site, the first instruction
that reads the returned table value and the six that follow it:

| consumer | sites | first read | continuation |
|---|---|---|---|
| stack-arg (pushed as a stack argument) | 7 | `push rax` | `call 0x5da8870` |
| register-copy (moved into a register) | 2 | `mov r13, rax` / `mov rcx, rax` | used immediately (one becomes a `div` divisor) |
| store (written to a stack slot) | 1 | `mov [rbp-0x170], rax` | reloaded later |

The dependency is a *value* dependency, not a bound: the callers never
compare or clamp the result, they pass it on. All seven `stack-arg`
sites feed the same builder at `0x5da8870`, so the contract is one
callee's parameter — the produced file size — and a wrong table entry
propagates into it rather than being caught at the call site. The two
`register-copy` sites compute with it instead: one divides by it
(`div rbp` at `0x5e105dc`), so a zero result would be a division by zero
inside the caller.

## Claim anchors (target evidence)

Every behavioural claim above is anchored to the exact instruction in the
target image that carries it. `semantics.tsv` lists 15 anchors (`claim`,
`va`, `size`, `bytes`, `instruction`, `note`) — the options-pointer copy,
the level/base compare and its `setl`, the style move into `dil` and its
low-byte `test`/`setne`, the `or`-combine and both branches, the
low-byte flag compare, the two sign-extending index paths, the two 64-bit
table reads, and the single `ret`. `verify.py` regenerates the file and
re-reads each anchor's bytes from the binary, so the claim set is checked
against the artifact rather than against another model; the test suite
asserts the same.

The model is additionally cross-checked against a **decoded execution of
the routine's own committed instructions**: `max_file_size_for_level_decoded`
interprets the instruction stream in main.txt (whose bytes `verify.py`
hashes against the binary) on a small machine model, implementing exactly
the instructions this routine uses and raising on anything else. Every
committed ledger row, the whole 2,400-case sweep and a 20,000-input random
differential are checked that way, so the closed form is validated against
the target's instructions rather than only against a second restatement.

## Evidence notes

- main.txt is the raw `objdump -d` listing of the whole routine, verbatim
  instruction text (with the encoded bytes); the objdump symbol header is
  normalized to the bare binary name and the nearest-symbol annotations
  objdump adds to branch targets are dropped, so the file carries no
  machine-specific path and no misattributed symbol.
- frames.txt is the .eh_frame entry covering the routine
  (`pc=000000000607f450..000000000607f48a`), read with `readelf -wf`.
- relocations.txt records the empty relocation set and both body hashes
  from the vendor census.
- cases.tsv is a **reviewable** 300-case ledger (75 per family under
  `matrix`, `style`, `base`, `random`). The exhaustive 2,400-case sweep
  and the random differential are re-derived in memory by the tests and by
  verify.py; the committed ledger is asserted to be the generated subset.
- records.json holds semantic records (context, caller census,
  observations, unknowns, environment limits); instruction detail lives
  only in main.txt.
- verify.py re-checks the manifest, regenerates main.txt byte-for-byte and
  every instruction's bytes against the raw binary, regenerates both
  censuses and the claim anchors, checks the FDE bounds and the census body
  hash, replays the ledger, cross-checks every committed row against the
  decoded execution, and asserts the ledger is the generated subset.

Reproduce the excerpt:

    objdump -d --start-address=0x607f450 --stop-address=0x607f48a \
        artifacts/node/115/hl-node

## Unknowns

- The C-level meaning of the five arguments beyond their register roles.
  The symbol name says which parameters the source declares; what the
  compiled `style`, `base` and `flag` values mean at each call site is not
  established here (they are runtime values).
- What the table at `options + 0x1e0` holds beyond "64-bit entries indexed
  by the selected index": its length, its fill order and whether the
  callers ever pass an index past its end are not established. The routine
  itself does not bound-check.
- The adjacent `rocksdb::MaxFileSizeForL0MetaPin` at
  `0x607f490..0x607f4bb` (43 bytes, `rawEqual`, in the same
  `cf_options.o`) is **not** covered here; it is a separate window and is
  left for its own packet.
- The body is byte-identical in 3 identical source objects
  (`identical_source_count` = 3); only address 0x607f450 is bound.

## Environment limits

This work used static disassembly only (`objdump`/`readelf` on the
digest-verified local binary). No cargo/rustc, Ghidra or git-lfs was
needed, and the captured node was never executed. The model in
tools/rocksdb_max_file_size_for_level_607f450_115.py is a Python
transcription of the pinned algorithm, cross-checked by decoding and
executing the routine's own published instruction bytes on a small machine
model — not a build of node or rocksdb code.
