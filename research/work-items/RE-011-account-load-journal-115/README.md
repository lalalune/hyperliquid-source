# RE-011: reconstruct node #115 EVM account load into the journal cache (0x4323870, 0x5463980) and code-object install (0x433c700)

With this packet you can rebuild, as runnable code, how the node #115 EVM brings one account into the per-block account
cache before an opcode touches it: the cache hit and stale-entry refresh rules, the warm/cold decision and the refusal
status 2, the cold-access journal record, the database read with its error drops, the account constructor call, the
default empty account (checked Arc refcount increment, TLS-derived hash seed, uninitialised stack bytes), the exact
hashbrown insertion into the 0xa8-byte bucket table, and the follow-up step that installs the account's code object. The
tool proves the reconstruction against the real machine code of all three bodies in 14,600 cases and 160 controls.

- Component ID: `evm` (task RE-011, EVM/forks: one bounded EVM adapter path)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No reference source is used.
- Claim status:
  - Observation: code bytes, extents, GOT slot targets, call sites, constants, and the agreement of the evaluated machine
    code with the model on every case.
  - Inference: the roles named below (account cache, journal, warm set, code object) and the reading of the callee
    contracts; the names are labels, not recovered symbols.
  - Unresolved: the callee bodies listed under Limits, the unwind landing pads, and the owner of the 0xa8-byte entry
    type.
- Scope:
  - Included: `0x4323870` (340 instructions, 1696 bytes, the ordinary loader), `0x5463980` (314, 1546, its twin with
    different callees and without the database error branch), `0x433c700` (82, 291, code-object install).
  - Excluded: all callees (stubbed with explicit contracts shared by the evaluator and the model), the unwind landing
    pads (reached only while unwinding), and the code-object install twin `0x54793e0`.

## Reproduce

From the repository root, with Python 3 standard library only (the binary is never executed, no external program is run):

```
python3 tools/re11_account_load115.py --out research/work-items/RE-011-account-load-journal-115
python3 -m unittest tests.test_re11_account_load115
python3 tools/artifacts.py verify
```

The tool checks the SHA-256 of the input binary first and fails on a mismatch. The regeneration writes only into the
`--out` folder, takes about 30 seconds and stays below 400 MB of memory. Every output is byte-identical between runs
(`MANIFEST.sha256` lists the hashes). The evaluator is the concrete x86-64 evaluator of `tools/re11_access_list115.py`
with three additions in this tool: the `lock` prefix, signed conditions (`jle`/`jg` after `lock inc`) with a real
overflow flag for `inc`/`add`/`sub`, and executed-address tracking.

## Evidence

Coordinates are virtual addresses of the node #115 ELF; the extents come from the `.eh_frame` FDE of each entry point
(`constants.json`). `decoded-instructions.tsv` lists every instruction of the three bodies with its bytes and whether any
case executed it (324/340, 298/314 and 75/82; the rest are the unwind landing pads and the arms the cases cannot reach).

| body | address | bytes | role |
| --- | --- | --- | --- |
| ordinary loader | `0x4323870` | 1696 | account into the cache, database error variants |
| twin loader | `0x5463980` | 1546 | same flow, callees `0x4ef78b0` and `0x54419e0`, no error branch |
| code install | `0x433c700` | 291 | install the code-object Arc at account+0x70 |

Calling convention (observation from the prologues and uses): `rdi` output block, `rsi` state, `rdx` pointer to the
database handle, `rcx` 20-byte address, `r8b` the "refuse cold" flag; returns `rax = rdi`. State offsets: journal Vec
capacity `+0x18`, pointer `+0x20`, length `+0x28`; warm set `+0x48`; account map header `+0xc8` (control pointer, mask,
growth left `+0xd8`, items `+0xe0`); epoch `+0x120`. Map entries are `0xa8` bytes below the control array: 20-byte key at
`-0xa8`, 4 junk bytes, a `0x90`-byte account at `-0x90` with its epoch at `+0x88` and flag byte at `+0x8c` (bits `0x10`
reverted, `0x40`, `0x80`). Output block: account pointer `+0`, journal Vec `+8`, state+0x70 `+0x10`, database handle
`+0x18`, epoch `+0x20`, address `+0x24`, status byte `+0x38`.

Observed rules (each one is exercised by named case kinds in `cases.tsv` and by a negative control):

1. The entry lookup returns tag 0 (occupied, bucket end pointer) or the vacant triple (map, hash, key).
2. Occupied and current (same epoch, flag `0x10` clear): return the account with status 0 and touch nothing.
3. Occupied but stale: run the warm test; refuse (status 2, nothing else written) unless `((r8b ^ 1) | al) == 1` (this
   byte-exact test differs from the vacant test below); otherwise clear flag `0x10`, store the epoch, call the `0x40`
   callback when that bit was set and clear it, call the touch callback, clear `0x80`, push the journal record, and
   return status `al ^ 1`.
4. Vacant: run the warm test and refuse when `((r8b ^ 1) | al) == 0`; read the database; tag `2` is an error (kind 2 is
   a vtable call on the object, kinds above 2 a deallocation when the size is non-zero, kinds 0 and 1 nothing) and
   continues with the default account; the tag test is `rax == 2` first and then `eax == 1`, so a tag with upper bits
   set and low half 1 still reaches the constructor in `0x4323870`, while `0x5463980` compares the full 64 bits.
5. The constructor output gets the epoch stored at `+0x88`; the cache value is the first 4 bytes of the constructor
   output followed by the account.
6. The default account is: the empty-map template at `0x6484fa0` (`0x64a9948` in the twin); a hash seed computed as
   `t1 = fold((C ^ tls) * A)` with `A` the stack address of the account buffer, `fold(x) = low64 ^ high64`, written back
   to the TLS counter at `fs:-0x578`, then `seed = fold(t1 * K)`, with `C = 0x13198a2e03707344` and
   `K = 0xa4093822299f31d0`; 32 zero bytes, then the 32 rodata bytes at `0x4585a0`; the code-object Arc pointer at
   `+0x70`; four bytes of uninitialised stack at `+0x7c`; epoch; flag byte 8; three more uninitialised stack bytes. The
   Arc cell at `[0x64e6c78]` is lazily initialised when its state dword is non-zero; the refcount increment is
   `lock inc` followed by `jle`, so `0x7fff_ffff_ffff_ffff` passes (SF equals OF) while `0`, `-1`, `-2` and
   `0x8000_0000_0000_0000` reach `ud2`. The global seed block byte `+0x30` must be 2 or the initialiser runs.
7. Cold access (`al` low byte zero) appends the journal record (tag 0, 20 address bytes) after growing the Vec to
   `max(2 * cap, 4)` when it is full; the output status is `al ^ 1`.
8. Insertion is the hashbrown SSE2 probe: group at `hash & mask`, first control byte with the top bit, wrap through the
   group at the table start when the slot found is a mirror of a full bucket, stride 16, 32, 48 ...; the control byte
   and its mirror get `hash >> 57`, growth left drops by the low bit of the old control byte, items grows by one.
9. `0x433c700`: return when `account+0x70` is set; compare the 32-byte code hash at `+0x48` with the two rodata halves
   `0x4537f0` (low) and `0x452020` (high); a different hash asks the database code read `0x3d48830` (tag 5 with a
   non-zero pointer is the code Arc, tag 5 with zero and tags 0 and 1 mean none, low half 2 is the vtable drop, larger
   halves free the buffer when the size is non-zero); with no code the empty-code Arc cell is used with the same
   checked increment.

Files (all generated by the tool, listed in `MANIFEST.sha256`):

- `cases.tsv`: one row per case (variant, case number, kind, key inputs, outcome class, callee event names, result,
  executed steps, match).
- `outcome-classes.tsv`: case counts per variant and outcome class.
- `decoded-instructions.tsv`: instruction table of the three bodies with the executed flag.
- `callee-sites.tsv`: every call site (direct or through a GOT slot, with the relocation kind of imports) with the
  contract assigned to its target.
- `constants.json`: extents, body SHA-256 values, checked instruction bytes, GOT slots, rodata and template words.
- `negative-controls.tsv`, `unexecuted-mutants.tsv`, `summary.json`, `measure.json`.

## Implementation and comparison

`tools/re11_account_load115.py` evaluates the real instruction bytes of each body with the concrete evaluator and
compares the result with `reconstruct()` / `reconstruct_prep()`, two pure-Python functions. The callees are stubbed with
the contracts of the `Contracts` class; the same Python methods serve both the evaluator stubs and the model, so a
difference can only come from the loader code itself. Each stub clobbers every caller-saved register with a junk value, so
a body that relied on a register surviving a call would fail. The comparison covers the full byte image of the state,
journal buffer, grown heap buffer, map (entries and control bytes), output block, address, database handle, Arc cell,
Arc counter, hash-seed block and TLS page, the ordered callee event list (including every `memcpy` length), the return
value, and the callee-saved registers and stack pointer on return; a `ud2` outcome compares the event list and status.

Cases (`make_case`, deterministic from a SHA-512 stream): 6,000 per loader and 2,600 for the code install. Kinds cycle
through occupied-current, stale epoch, reverted flag, stale refusals, vacant with database hit, none, error variants,
vacant refusals, refcount edges, odd tags, dense tables whose first groups are full, and probe tables whose later groups
hold the only free slots. Fields drawn at random or from edge lists: flag byte (including values above 1), the `al`
return with junk upper bytes, epoch edges, table size 4 to 64 buckets, tombstones, growth-left zero, journal full and
empty, hash seed state, lazy cell state, refcount edges.

Controls (160): 17 model mutants (wrong epoch test, ignored flag `0x10`, wrong refusal tests, plain status, 64-bit tag
test, simplified overflow rule, TLS without stack address, truncated seed, zeroed stack residue, journal on warm, wrong
top-7 shift, growth always decremented, wrong `memcpy` length, swapped code-hash halves, 32-bit tag test, free of a
zero-size buffer), 140 corrupted code bytes (every executed conditional jump inverted and the lowest byte of every
executed immediate flipped, in all three bodies) and 3 input controls (a binary with one flipped byte, a code read
outside `.text`, the ordinary-loader model run against the twin's machine code). A compare whose flags are overwritten by
the next `test` is skipped as an equivalent mutant (the `cmp rax,3` before the free path); five conditional jumps in
unwind landing pads are never executed and are listed in `unexecuted-mutants.tsv`.

Rust: not yet implemented. The model is Python only; no Cargo.lock, build flags or two-build comparison apply.

## Results and limitations

Machine-readable metrics are in `summary.json` and `measure.json`: 14,600 cases (6,000 + 6,000 + 2,600), 0 mismatches,
1,737,044 evaluated instructions, 160 of 160 negative controls detected. Outcome classes per variant are in
`outcome-classes.tsv` (for example 2,498 ordinary-loader default accounts, 867 constructor loads, 1,307 occupied
refusals, 104 `ud2` outcomes).

Limits:

- The callees are contracts, not reconstructions: the entry lookup (`0x3ed7040`, `0x4ef78b0`), the database reads
  (`0x3d48970`, `0x54419e0`, `0x3d48830`), the warm test (GOT `0x64ea6d8`), the account constructor (GOT `0x64e7020`),
  the touch and `0x40` callbacks, the Vec grow (GOT `0x64e68e8`, `0x64e6cf0`), the lazy initialisers (`0x435059c`,
  `0x5b084ff`), the seed initialiser (GOT `0x64e22e8`) and the Arc slow drop (GOT `0x64e4fa8`). Their real bodies can
  differ from the contracts in effects the loaders do not observe.
- The stub hash of the lookup is a stand-in (a SHA-256 prefix); the real hasher and its seed are not part of this packet,
  so the slot positions here are those of the stub hash, not of the node.
- The "uninitialised" stack bytes are modelled from the deterministic stack fill of the harness; in the node they are
  whatever the caller left there, so those 7 bytes of a default account are not a stable value.
- The unwind landing pads (about 16 instructions per loader) and the `lock dec` arm of `0x433c700` are unreached.
- The twin `0x54793e0` (a code-cache insertion with a hash-table entry) is not included.
- No component gate is requested; the packet does not cover the whole `evm` component.

Next question: reconstruct the entry lookup `0x3ed7040` with its foldhash seed (the hasher behind GOT `0x64e6458` is the
twin's insert call), then the account constructor GOT `0x64e7020`, so the stub hash and the constructor contract can be
replaced by real bodies.
