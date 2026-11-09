# RE-011: node #115 EVM storage and account state access — SLOAD, BALANCE/EXTCODE*/SELFBALANCE, EXTCODECOPY and the transient writer

With this packet the node #115 EVM reconstruction can implement the interpreter's state-access opcodes as
runnable pure-Python functions, checked against the real machine code: how `SLOAD` finds the executing account
in the host account map and charges the cold surcharge; how `BALANCE`, `EXTCODESIZE`, `EXTCODEHASH` and
`SELFBALANCE` turn a stack word into an address and use the two account loaders (cold-load skip, cold-account
charge, spec-dependent "empty" rule); how `EXTCODECOPY` reuses those loaders with `load_code = 1` and then
prices, grows, clones, clamps, copies and zero-fills account code into memory, including every overflow and
bound panic; and how the `TSTORE` writer `0x2972390` updates the two-level transient map and its journal. One
tool, `tools/re11_storage_account_extcodecopy115.py`, runs all 16 function bodies on one shared x86-64
evaluator. **26,400 / 26,400 cases match** the four reconstructions, and **121 / 121 negative controls** are
detected.

- Component ID: `evm` (task RE-011, EVM interpreter opcodes and state access).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6` (new files only). No reference
  source was copied. The Keccak-256 used to check the empty-code-hash constant is the public FIPS 202
  permutation, written from the specification.
- Claim status:
  - **observed**: opcode-table slots, FDE extents, relocations and GOT targets, pinned instruction bytes, the
    empty-code-hash halves in `.rodata`, and every compared case result (evaluated from the target bytes);
  - **inferred**: opcode names (from the opcode-table index), field roles ("account map", "cold surcharge",
    "cold account price", "status flags", "journal", "reserve", "grow"), and fork naming of the spec bytes;
  - **unresolved**: the bodies of the stubbed callees (storage loads `0x4e33680` / `0x433bcf0`, state loaders
    `0x5463980` / `0x4323870` / `0x2971760`, code loader `0x299f1c0`, memory growth `0x45244c0`, inner reserve `0x5be4ac0`, journal grow
    `0x43bc980`), the live parameter values and the NOBITS hash seed value.
- Scope (four families; family prefix in file names and tool symbols):
  - `sl`: SLOAD handler `0x2993ff0..0x2994402` and its position twin `0x2993bd0..0x2993fe2` (opcode `0x54` of
    the RELATIVE tables `0x64414b0` / `0x64421a0`), 236 instructions each.
  - `ar`: BALANCE `0x2994f20`/`0x2995080`, EXTCODESIZE `0x2990b00`/`0x2990ca0`, EXTCODEHASH
    `0x29906a0`/`0x29908d0`, SELFBALANCE `0x2990f10`/`0x2990e40` (copy 0 / copy 1 named by tables
    `0x6441210` / `0x6441f00`) and the account loaders `0x2990fe0` / `0x2991160`.
  - `tw`: transient writer `0x2972390..0x2972c20` (511 instructions), called by TSTORE `0x2994e90` at
    `0x2994f0c`. The TSTORE handler itself belongs to the separate open TLOAD/TSTORE packet and is not
    re-reconstructed here; only its call site is pinned.
  - `ec`: EXTCODECOPY `0x298fca0..0x2990193` / `0x29901a0..0x2990693` (slot `0x3c` of the same tables
    `0x6441210` / `0x6441f00`; copy 1 = copy 0 + `0x500` with the same instruction-length sequence), calling the
    `ar` account loaders `0x2990fe0` / `0x2991160`, memory growth `.got 0x64e6de0`, `memcpy`/`memset`
    (dynsym names), shared-pointer drop `0x64e4fa8`, the static Bytes vtable `0x6451328` and seven panic
    location records.
  - Excluded: SELFDESTRUCT, SSTORE, the dispatcher, and the callee bodies listed as unresolved.
    No component gate is advanced. The surrounding RE-016 "materializer/exporter" names are not used.

## Reproduce

From the repository root, with the authenticated #115 artifact present. Python 3.12 standard library plus
`tools/elf_index.py` and `tools/fde_extents.py`; no external program is invoked and the binary is never executed.

```sh
python3 tools/re11_storage_account_extcodecopy115.py --out research/work-items/RE-011-storage-account-extcodecopy-115
python3 -m unittest tests.test_re11_storage_account_extcodecopy115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-011-storage-account-extcodecopy-115 && sha256sum -c MANIFEST.sha256)
```

Determinism check (two empty temporary directories, then `diff -r`):

```sh
python_exec=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$python_exec" tools/re11_storage_account_extcodecopy115.py --out <tmp-a>
PATH= PYTHONHASHSEED=12345 TZ=Asia/Seoul "$python_exec" tools/re11_storage_account_extcodecopy115.py --out <tmp-b>
diff -r <tmp-a> <tmp-b>
```

The tool checks the full SHA-256 first, then (per family) the FDE extents, relocations and pinned bytes, and
fails on any difference. It evaluates every case and every negative control and fails on any mismatch or
missed control. The four families run in four processes; a full run takes about one minute.
`--full` writes the whole case listings; by default every 10th row is committed and the SHA-256 of each full
listing is pinned in `summary.json` (`families.<f>.full_cases_tsv_sha256`).

## Evidence

| File | Content |
| --- | --- |
| `summary.json` | totals, and per family: case count, sampled rows, full-listing SHA-256, control counts, family detail (coverage, outcome classes) |
| `sl-constants.json` | SLOAD FDEs, table slots, load call sites and GOT targets, hash seed slot (NOBITS target `0x64ffe90`), pinned bytes |
| `sl-decoded-instructions.tsv` | every SLOAD/twin instruction with its executed flag (236/236 executed in each copy) |
| `sl-cases.tsv` | every 10th of 4,400 SLOAD cases: inputs, outcome, load call, result, match |
| `sl-outcome-classes.tsv`, `sl-negative-controls.tsv` | 26 outcome classes; 23 controls |
| `ar-functions.tsv` | the 8 handler copies and 2 loaders: FDE extent, size, SHA-256 of the code bytes |
| `ar-constants.json` | table slots, pinned bytes, GOT slots, panic sites, empty-hash halves, displacements, result codes, spec gates, loader tags |
| `ar-decoded-instructions.tsv` | every instruction of the ten bodies with its reach class (852/908 executed) |
| `ar-cases.tsv` | every 10th of 6,000 account-read cases |
| `ar-outcome-classes.tsv`, `ar-negative-controls.tsv` | 46 outcome classes; 33 controls with the first detecting case |
| `tw-constants.json` | writer FDE, body hash, call sites, `.got` stub targets, offsets, journal record layout, checked bytes |
| `tw-coverage-runs.tsv` | executed/unexecuted runs of the 511 instructions (399 executed) |
| `tw-cases.tsv` | every 10th of 6,000 transient-writer cases |
| `tw-outcome-classes.tsv`, `tw-negative-controls.tsv` | 16 outcome classes; 25 controls |
| `ec-functions.tsv` | both EXTCODECOPY copies: FDE extent, size, SHA-256 of the code bytes |
| `ec-constants.json` | table slots, loaders, 45 pinned instructions (39 also checked in copy 1), GOT slots with dynsym names, static Bytes vtable, panic locations, field offsets, result codes, rip references |
| `ec-decoded-instructions.tsv` | every instruction of both copies with its reach class (536/572 executed) |
| `ec-cases.tsv` | every 10th of 10,000 EXTCODECOPY cases (5,000 per copy) |
| `ec-outcome-classes.tsv`, `ec-negative-controls.tsv` | 91 outcome classes; 40 controls with the first detecting case |

Coordinates are virtual addresses of the #115 ELF; file offsets come from the section headers with NOBITS
sections excluded. Human-readable excerpt (GNU objdump 2.42, Intel syntax; not used by the tool):

```text
2990ffe: mov  rax,QWORD PTR [rax+0x80]      ; ar loader 0: cold account price
2991011: cmp  r12,rax / setb r8b            ; skip_cold_load = remaining < price
2991126: sub  r12,[rsp+0x10] / jb -> tag 2  ; cold charge, stored only on success
2994f0c: call 2972390                       ; TSTORE -> transient writer (rdi = host+0x270)
298fe2b: mov  ecx,0x1                       ; ec copy 0: account loader with load_code = 1
```

## Implementation and comparison

One file, four reconstructions on one evaluator:

- **Shared core** (top of the tool): digest-checked `Image` over `tools/elf_index.py`/`tools/fde_extents.py`,
  a fixed-pattern x86-64 decoder and a concrete `Machine`/`TraceMachine` (union of the instruction forms the
  four families use), `load_image()` reading the binary once per process. The SLOAD account map and the
  transient map use the same seed slot `0x64dfa78` and the same folded address hash; a test checks that the two
  family hash reconstructions agree. EXTCODECOPY and the account reads share the opcode tables, the loader
  addresses, the shared-pointer drop slot and the address derivation; a test checks that both families agree.
- **`sl_model()` / `sl_addr_hash()` / `sl_build_table()`** — SLOAD:

  ```
  if stack_len == 0: return 0x2c
  berlin = spec > 6
  h = fold(fold(a[0:8] ^ secret, a[8:16] ^ seed) ^ a[16:20], seed)   # fold(x,y) = lo(x*y) ^ hi(x*y)
  probe host map (ctrl +0x338, mask +0x340, items +0x350, 0xa8-byte buckets; h2 = h >> 57)
  miss: return 0x20 if berlin else 0x36
  (ptr, tag) = load(ctx, &key, flag = berlin and gas < params[0xc8])
  tag == 2: return 0x20 if berlin else 0x36
  berlin and tag & 1: gas < params[0xc8] -> 0x20, else gas -= params[0xc8]
  stack top = ptr[0x20..0x40]; return 0
  ```
- **`ar_model()` / `ar_load_account()` / `ar_is_empty()`** — account reads:
  - address = low 160 bits of the top word, passed big-endian;
  - loader: `skip = remaining < params[+0x80]`; tag 2 = error (gas unchanged); a cold load charges the price
    (borrow -> tag 2, gas unchanged); the code loader runs before the charge; output tag 0, balance pointer,
    cold, empty;
  - empty rule: host spec `> 2` -> content rule (hash Keccak("") or 0, balance 0, nonce 0); `<= 2` ->
    `(flags & 0x08) and not (flags & 0x04)`;
  - BALANCE: `0x2c` on empty stack, `0x20` on load error / cold OOG, else balance replaces the top;
  - EXTCODESIZE: `load_code = 1`, `None` bytecode panics (location `0x6443808`), else pushes length `+0x50`;
  - EXTCODEHASH: `0x2b` when spec `< 5` (before the stack check); recomputes the content-empty rule inline;
  - SELFBALANCE: `0x2b` when spec `< 6`; loads its own address with `skip = 0`, no cold charge; error -> `0x36`;
    stack limit `0x400` checked after the load.
- **`tw_model()` / `tw_apply()`** — transient writer: map at argument `+0xf0` (0x40-byte outer buckets keyed by
  the 20-byte address, each with an inner table header); value 0 removes the key (EMPTY vs DELETED by the
  hashbrown neighbour rule, growth_left restored on EMPTY, items − 1) and journals the old value; a non-zero value
  reserves the inner table when growth_left is 0 (`.got 0x64e6c90`), then overwrites or inserts and journals the
  old value unless it equals the new one; journal record 0x58 bytes, tag `0x0a`, address, key, old value; full
  vector grows through `.got 0x64e6cf0`; a new address reaches the thread-local RandomState boundary.
- **`ec_model()`** — EXTCODECOPY:
  - fewer than 4 words -> `0x2c`; the 4 words are popped **before** the operand checks; size wider than 64 bits
    -> `0x24`; memory offset wider than 64 bits -> `0x24` only when `size != 0`;
  - `cost = ceil(size/32) * params[+0x20]` (params at `host+0x250`) saturated to `2^64-1`; remaining gas is
    stored before growth;
  - growth is called with `ceil(min(off+size, 2^64-1)/32)` only when that exceeds `interp+0x170`; a nonzero
    growth result byte is returned as is;
  - account load with `load_code = 1`: tag 2 -> `0x36` or `0x20` by error-byte bit 0; bytecode from
    `account+0x48` (tag 0) or `record+0x50` (tag 1); `None` panics; `original len (+0x50) > padded len (+0x40)`
    panics; empty code uses the static vtable with no clone, otherwise the Bytes are cloned and truncated;
  - code offset `min(off, len)` (or `len` when wider than 64 bits);
  - copy path (`co < len`): copy `min(co+size, len) - co` bytes, then zero-fill the rest; three overflow panics
    and **no** memory bound check; zero-only path (`co >= len`): an overflow panic, then the bound
    `off+size <= mem_len - frame_offset`; `memset` always runs, even for 0 bytes;
  - borrow flag at `memory+0x10` set to -1 without a check and restored to 0; the Bytes are dropped through
    `vtable+0x20` with the original length, then a nonzero tag releases the record's shared pointer.

Each case compares the result code or panic site, the whole interpreter/host/parameter/table/journal regions
the body may touch, the ordered stub calls with their arguments, untouched bytes, and the callee-saved
registers. Case fixtures are built with the **reconstructed** hashes, so a hash error shows up as a probe miss.

## Results and limitations

- **26,400 / 26,400 cases match** (SLOAD 4,400; account reads 6,000; transient writer 6,000; EXTCODECOPY
  10,000), 179 outcome classes in total (26 + 46 + 16 + 91).
- **121 / 121 negative controls detected**: 9 + 13 + 12 + 16 = 50 model mutants, 12 + 18 + 11 + 22 = 63
  single-byte code mutants, and 8 input controls (a flipped binary byte fails the digest check and an
  out-of-`.text` fetch is refused, each exercised once per family on different bytes).
- Instruction coverage: SLOAD 236/236 in each copy; account reads 852/908 (the 56 unexecuted are tag-1 arms
  unreachable because the loaders only write tags 0 and 2, and code after noreturn panic calls); transient
  writer 399/511 (probe continuations, the new-address TLS path, cold outer-insert/reserve/panic blocks);
  EXTCODECOPY 536/572 (the 36 unexecuted are the `ud2`, landing pads and jumps after noreturn panics, each
  labelled; the tool fails if any reachable instruction is not executed).
- The merged evaluator reproduces the per-family tools it replaces byte-for-byte: every full case listing,
  constants file, decoded-instruction listing, outcome table and control table is identical (for EXTCODECOPY the
  full case listing hashes to the same SHA-256 as the per-family tool's all-rows hash).
- EXTCODECOPY rows marked `forced-growth` depend on the growth stub accepting huge sizes; loader tag 1 is
  stub-only for EXTCODECOPY because the loaders write only tags 0 and 2.
- The callees listed as unresolved are contract stubs that check their arguments; their internals are not
  claimed. Warm/base opcode gas is charged by the dispatcher, outside these bodies.
- The hash seed (`0x64ffe90`, NOBITS) and parameter values are case inputs, not recovered constants.
- Transient tables smaller than 16 buckets are not generated, so the small-table fix-up is unverified; journal
  record padding bytes `0x15..0x18` (uninitialised stack) are not compared.

## Next question

What do the stubbed state loaders `0x5463980` / `0x2971760` do with `skip_cold_load`, and does the outer
transient-map insert (new address, RandomState path) match the inner insert rule? Does memory growth
`0x45244c0` reject every EXTCODECOPY `forced-growth` combination (which would make the copy-path panics
`0x64bfd40/58/70` unreachable in practice)?
