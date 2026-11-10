# vaults: reconstruct ten vault-transfer result wrappers of node #115 (0x50a5ce0 .. 0x5436600) and prove them against the bytes

The group of 18 callees of the 4,304-byte action body at `0x55faa80` turns out to be a family of thin result wrappers around a few real
decisions, and this packet fixes those decisions from the #115 bytes: the exact error codes and their order (`0x91` state denied, `0xfa`
index at or above the limit, `0x92` flag clear, `0x154` amount at or above `0xccccccccccccccc` = `(2^63-1)/10`), the conversion rule of the
transfer logger (`0x54f2840`: amount and clock are both divided by `1000000.0` as IEEE doubles and handed to a recorder slot together with
the 20 byte key), and the byte-exact record shuffles of the forwarders, so that a Rust reconstruction can implement each wrapper as a small
pure function with the callee as a parameter. Ten of the 18 group members were rebuilt and run as real code in a small x86-64 evaluator;
30,043 generated cases agree with a hand written rule list in result bytes, outcome and ordered callee calls (0 mismatches), and 470
negative controls (466 detected, 4 equivalent dead stores or unobservable stack addresses, each justified in `equivalent-mutants.tsv`)
were run.

- Component ID: vaults (`l1/action/vault_transfer.rs`, with `l1/qtys/*.rs` and `l1/dex_registry/clearinghouses.rs` call sites); no TASKS row
  exists for vaults, the nearest dependency is RE-007 margin / risk
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: base `0781ce04826eeefd89fe336cb8ea073be0c1de30` of the workspace checkout; no reference source was
  copied (every name below is an inference from the bytes; node #94 was not used)
- Claim status: observation for addresses, offsets, constants, branch order, error codes, record layouts and call order; inference for the
  role names (state gate, amount bound, transfer log, key forward, list forward, pair forward) and for the units behind `1000000.0`;
  unresolved for the bodies of every callee that is a stub here (listed below) and for the 8 group members that are not rebuilt (the root and seven others)
- Scope included and excluded: included - the FDE bodies `0x50a5ce0`, `0x58c23a0`, `0x543ac80`, `0x54f2840`, `0x532fc60`, `0x534bd60`,
  `0x5208890`, `0x532f980`, `0x5208370`, `0x5436600` (746 decoded instructions); excluded - the root `0x55faa80` itself, the group
  members `0x4fb7b60`, `0x50a5a00`, `0x514ac50`, `0x54358a0`, `0x54e3030`, `0x55f56a0`, `0x5620aa0` and every other
  callee (recording stubs with written contracts); no component gate is requested.

## Reproduce

Working directory: repository root, Linux x86-64, Python 3 standard library plus the shared `tools/fde_extents.py` and `tools/elf_index.py`.
The tool never runs the binary and never calls objdump, readelf or any other program; the digest of the input is checked first.

```
python3 tools/artifacts.py verify
python3 tools/vaults_transfer_wrappers_115.py --out research/work-items/vaults-transfer-wrappers-115
(cd research/work-items/vaults-transfer-wrappers-115 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_vaults_transfer_wrappers_115
```

One regeneration takes about 18 s and 460 MB of resident memory (`ru_maxrss` of the child); two runs with `PYTHONHASHSEED=1 TZ=Asia/Seoul`
and `PYTHONHASHSEED=777 TZ=America/Los_Angeles` were compared file by file and are byte identical to the committed folder. The 36 tests take
about 22 s.

## Evidence

Observations (all from the ELF bytes; `decoded.tsv` lists every instruction of the ten bodies, `fields.tsv` every pointer displacement):

1. The action body `0x55faa80` (1,020 instructions, 108 branches) calls these members directly (`direct-callers.tsv`): `0x50a5ce0` at
   `0x55faec7`, `0x58c23a0` at `0x55fac78`, `0x543ac80` at `0x55fadcd`, `0x54f2840` at `0x55fad3f`, `0x532fc60` at `0x55fb414`,
   `0x534bd60` at `0x55fb153`, `0x5208890` at `0x55fb0dd`, `0x532f980` at `0x55faef4`; `0x532f980` has a second caller at `0x5513464`
   (inside `0x5512e10`) and `0x54f2840` a second caller at `0x551c978` (inside `0x551c360`). The `Location` records reached from the
   subjects name the sources `l1/src/action/vault_transfer.rs:27:18` (argument frame of `0x532f980`) and
   `l1/src/dex_registry/clearinghouses.rs:11:29` (the `Result::unwrap()` failure inside `0x54f2840`).
2. Result convention. A wrapper returns through a pointer in `rdi`: byte 0 is the tag (`0xe` ok / `0xf` error for the gates, `0xc`, `0x1`,
   `0x5`, `0x4` for the widening wrappers) and, for errors, a 0x70 byte record at +0x10 whose first `u16` is the error code. A callee
   record whose first `u16` is `0x1a2` means success. Every error path copies the callee record to +0x10 without change (`a-error-copied`,
   `f-error`, `g-error`, `h-error`, `i-error`).
3. `0x50a5ce0` (192 bytes, 52 instructions): `if ctx[0x4349] == 0 and ctx[0x170a] == 3 -> 0x91`; `else if req[0x10] >= ctx[0xb8] -> 0xfa`;
   else one callee call `0x55c6d50(tmp, ctx, req[0x10])` and the tag test. Listing excerpt:
   ```
   50a5ce6: cmpb   $0x0,0x4349(%rcx)       50a5d03: mov    0x10(%r8),%r9
   50a5ced: jne    50a5d03                 50a5d07: cmp    0xb8(%rcx),%r9
   50a5cef: cmpb   $0x3,0x170a(%rcx)       50a5d0e: jae    50a5d3b      ; -> movw $0xfa,0x10(%rax)
   50a5cf8: movw   $0x91,0x10(%rax)
   ```
4. `0x58c23a0`, `0x543ac80`, `0x54f2840` all contain `movabs $0xccccccccccccccc` followed by an unsigned compare of an amount; at or above the
   bound the error record is `{code 0x154, u64 amount}` (at +0x10/+0x18 for the wrappers, at +0/+8 for the logger). `0x58c23a0` tests the
   bound before its callee, `0x543ac80` calls its first slot (`0x64e5b38`) before testing, and its success path joins the first record's
   first 15 bytes with the second callee's 0x70 byte record (`out[0] = 5`).
5. `0x54f2840` (720 bytes, 137 instructions, the largest subject): bound test first; then slot `0x64e7a68(tmp, st+0x1710, req, rdx, st+0x4a78,
   &{u64 st[0x60], u32 st[0x68]})`; a non-`0x1a2` result is copied whole (0x70 bytes); a record whose byte 2 is not 1 returns `0x1a2` and
   nothing else; otherwise, if `st[0x1340] == 0` the body fails `Result::unwrap()` (text at `0x7d3212`, 43 bytes, vtable `0x648c5f8`, Location
   above) with the `0x156` record as the error value; else it drops that `0x156` temporary (`0x44e0810`), allocates 20 bytes, copies
   `req[0x30..0x44]`, and calls the recorder `0x64ebc18(st+0x7c0, &{cap 1, ptr, len 1}, &{stamp, word}, tmp[3..0x23], &event)` with
   `event = {0x8000000000000000, f64(req[0x28]) / 1000000.0, req[0x20], f64(u64 at clock+0x4c0) / 1000000.0}`; the `u64 -> f64` of the clock
   is the usual `0x43300000/0x45300000` magic-number sequence, which equals one correctly rounded conversion (`clock_signed` is refused).
6. `0x532fc60`: `ctx[0x4e1d] == 0 -> 0x92`; byte `2` is accepted without effect; any other byte is stored at `obj+0x1c` after the guard
   pair `0x4dc91f0(ctx+0x4b68)` / `0x4da56b0` (the second returns the object).
7. Forwarders: `0x534bd60` moves the callee record's bytes `0..7` and `8..0x20` into `out[1..0x20]` (byte 7 dropped) with tag `0xc`;
   `0x5208890` passes `req[0..0x18]` by pointer, `req[0x18..0x50]` by a second pointer and `req[0x50]` as the last argument;
   `0x532f980` passes a 20 byte copy of `*rdx`, `0`, `0`, a pointer to a zero `u64`, and the stack arguments `(rdx, req, 0x64a4748)`;
   `0x5208370` clones `len` 16 byte items (guard: `len >> 60 != 0` or `(len << 4) > 0x7ffffffffffffff8` calls slot `0x64df498(0, size)`;
   an allocation failure calls `0x64df498(8, size)`) and forwards `{cap, ptr, len, byte}`, ok tag `1`; `0x5436600` clones two
   niche encoded byte strings (`0x8000000000000001` skips both, `0x8000000000000000` skips the first / second) and forwards a 0x38 byte
   frame plus a 17 byte tail, always with `out[0] = 4`.

Inferences: the error codes are `Result` error variants of the vault-transfer action; `1000000.0` is the USD scale already seen in the
vault withdraw gate; the logger writes a transfer event (amount, clock, key) to a per-state journal at `st+0x7c0`.

## Implementation and comparison

`tools/vaults_transfer_wrappers_115.py` carries (1) the shared offline x86-64 evaluator (ELF, FDE and decoder from the repository parsers) and
(2) a `Harness` that runs each subject body as real code and serves its callees through recording stubs with written contracts (argument
checks raise `Halt`, so a wrong frame is a mismatch, not a pass), (3) one rule list per subject written from the control flow (`spec_a` ..
`spec_j`) that returns the complete 0x80 byte result window, the outcome (return / panic) and the ordered stub calls. Memory outside the
result window (and the one object byte of `0x532fc60`, the clone buffers) must be unchanged, otherwise the run is a mismatch.

Comparison: 30,043 cases (43 named, the rest from a fixed LCG stream cycling over the ten subjects; boundary values at the amount bound,
at `i64::MIN` and `i64::MIN + 1`, at the size guard, empty and non-empty strings, allocation failure of the first and second clone).
Negative controls (470): 18 named wrong readings (`variants.tsv`, each refused by many cases), 24 structural controls (wrong digest,
mid-function address, NOBITS address, truncated section table, removed callee / slot stubs, an `int3` entry byte, five tampered constants),
and 428 one-byte edits of reached conditional jumps, immediates and displacements (`mutants.tsv`). 466 are detected. The 4 survivors are
equivalent: three are stores into a stack copy of the payload that is never read again (`0x534bd91`, `0x534bd99`, `0x520845b`) and one is
the stack address of a guard temporary that both guard calls take from the same register (`0x532fc8a`).

## Results and limitations

- 30,043 cases, 0 mismatches; 470 negative controls, 466 detected, 4 equivalent (`measure.json`); 722 of 746 instructions reached; the 24
  unreached instructions are unwind landing pads and the `ud2` after calls that never return (`unreached.tsv`).
- Stubs: `0x55c6d50`, `0x55f5af0`, `0x556e360`, `0x44e0810`, `0x54cd990`, `0x555f0d0`, `0x558f390`, `0x55687e0`, `0x556d0b0`, `0x4dc91f0`,
  `0x4da56b0`, slots `0x64e5b38`, `0x64e7a68`, `0x64ebc18`, allocator `0x64df480`, `0x64df498`, memcpy `0x64df508`, panic `0x64df6a0`. What
  they compute is unresolved; only the frames they receive are fixed here.
- The meaning of the state bytes `ctx[0x4349]`, `ctx[0x170a]`, `ctx[0x4e1d]`, of the limit `ctx[0xb8]`, and of `st[0x1340]` is not
  resolved. The role of the 7 non-root group members not rebuilt (`0x4fb7b60` 3,632 bytes, `0x514ac50` 3,024, `0x54358a0` 2,816, `0x54e3030` 1,808,
  `0x55f56a0` 1,104, `0x50a5a00` 544, `0x5620aa0` 32) is not examined; `0x50a5a00` is a keyed search over a 20 byte key set with error
  codes `0xfa`, `0x101` and `0x102`.
- Not claimed: no gate of the progress table is raised; nothing here is a statement about the node's economics.
- Next question: the callee `0x55c6d50` (reached with the checked index) and the recorder slot `0x64ebc18` at the receiver `st+0x7c0`:
  what is appended and under which key.
