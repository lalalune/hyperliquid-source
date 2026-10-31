# node-runtime: node #94 firewall/validator mismatch log in `0x4b28ff0` (silent unless a validator is missing or the firewall has more than 6 extras; throttled; no result)

Question: `0x4b28ff0` emits `firewall does not match validators`
(`firewall_ips.rs:65:13`) with two IP set differences. When does it log,
and what does it return? The can1357 lead (`node/firewall_ips.rs`,
`check_computed_ips`) logs and returns `Err` whenever either difference is
non-empty. Where does the binary differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`). The address is listed in
  `research/catalogue/seed-candidates.json` as a `node/firewall_ips.rs` seed.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: three windows in `0x4b28ff0` (entry and level gate, the whole
  non-unwind body from set construction to the log call, the final jump to
  the epilogue). Also the length test of the set-difference constructor
  `0x44c1ce0`, the non-unwind body of the elapsed-time helper `0x1447130`,
  the argument setup in the only caller `0x4524f70`, and the head of the wall
  clock `0x151cba0`. A scan of every `e8` call in `.text` and every
  RELATIVE addend finds the callers. Excluded:
  - the drop loops between `0x4b29190` and `0x4b292f6` and after `0x4b29511`
    (they are inside the body window, but not interpreted);
  - the bodies of the set builders `0x444fa30`, `0x444f680`, `0x444fbc0`,
    the abci builder `0x45c3d20` and the extract pass `0x42b9a50`/`0x49559c0`;
  - the seeds `0x28f6960` and `0x28f52d0`;
  - release #115.

## Reproduce

```sh
make verify
python3 tools/firewall_mismatch_static.py --json > research/work-items/firewall-mismatch-94/records.json
python3 -m unittest tests.test_firewall_mismatch_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; about 1 s). `records.json` is
its complete output; the test suite regenerates it and compares.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has 8
windows (379 instructions), one for each checked byte window. All 17
`records.json` VAs that fall inside a window are instruction starts there.
Each of the 60 `FACTS` entries and the 36 decoded call, branch and
RIP-relative operands must lie inside a checked window, or the tool refuses.
Six RELATIVE slots are resolved and checked.

## Evidence

### Arguments (observation)

The only direct call is `0x45250d1`, in the FDE `0x4524f70`. No RELATIVE
slot holds `0x4b28ff0`. The caller loads four pointers from `r13` and passes:

| Register | Value |
| --- | --- |
| `rdi` | `r15 + 0x588`, a BTreeMap `{root, height, len}` |
| `rsi` | a copy of 20 bytes from `[[r13]]` |
| `edx` | the byte at `[[r13+0x8]] + 0x8f2` |
| `rcx` | `[r13+0x10] + 0x8f8` |
| `r8` | `[r13+0x18]`, the throttle state |

The instruction after the call (`0x45250d6`) overwrites `rax`, so the caller
uses no return value. The callee's main path jumps from `0x4b29636` to the
epilogue `0x4b2902a` that the level gate also uses.

### Level gate (observation)

`0x4b29007` loads slot `0x576e928` (RELATIVE to `0x577b288`). If the dword
at `+0x50` is non-zero, an init call through slot `0x576e8b8` runs first.
Then the byte at `+0x48` is tested: values 1, 2, 15 and 17 (mask `0x28006`,
`cmp 0x11`) return at once; any other value continues.

### Sets and differences (observation)

- **firewall** `[rsp+0x128]`: collected (`0x444fa30`) from the `rdi` map.
- **abci** `[rsp+0x140]`: slot `0x5773b48` (RELATIVE to `0x45c3d20`) is
  called with the 20-byte value (tag byte 1), the `edx` byte and the `rcx`
  state. The result is collected by `0x444f680`.
- `0x44c1ce0` is called twice. Its length test reads `[rsi+0x10]` and
  `[rdx+0x10]` and takes the search path when `len(rsi) <= len(rdx) >> 4`.
  This is the tipping rule of Rust's `BTreeSet::difference`
  (`ITER_PERFORMANCE_TIPPING_SIZE_DIFF = 16`), with `self = rsi` and
  `other = rdx`.
  - `[rsp+0x110]` = abci − firewall (`rsi = 0x140`, `rdx = 0x128`). A pass
    then runs over it (`0x42b9a50` with `ecx = 2`, then `0x49559c0` until it
    returns 0). It gets `&[rsp+0x120]` (the set length) and `[rsp+0xb0]`,
    which holds the `rdi` pointer at that moment (`r14`, kept from `rdi` at
    `0x4b29004`).
  - `[rsp+0xb0]` = firewall − abci (`rsi = 0x128`, `rdx = 0x140`).

### Log gate (observation)

```text
if len([rsp+0x110]) == 0 and len([rsp+0xb0]) <= 6: skip      ; 0x4b293d3, 0x4b293de
now = wall clock (slot 0x576e8a0 -> 0x151cba0, clock_gettime(0))
if state.last (+0x8, 12 bytes) is set:                        ; dword +0x8 != 0
    if elapsed(now, last) <= state.interval (f64 +0x0): skip  ; ucomisd / jbe
state.last = now
log "firewall does not match validators @@ [abci_minus_firewall: {}] @ [firewall_minus_abci: {}]"
    with [rsp+0x110], [rsp+0xb0]; formatter 0x458bde0; firewall_ips.rs:65:13
```

`elapsed` is slot `0x576e8c0` (RELATIVE to `0x1447130`). It compares
`(date i32, secs u32, frac u32)` and panics with `Time Sub {} {}` when
`now < last`. Otherwise it gets `(secs, nanos)` from slot `0x576eaa0`
(RELATIVE to `0x151d1b0`) and returns `(secs·1e6 + nanos/1000) / 1e6`, which
is seconds truncated to microseconds. A NaN comparison also skips.

The template's first byte is `0x3c`. In rustc's packed format this is the
literal length (60), not text.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Inputs | a firewall map, a 20-byte value, a byte and a state pointer; both sets and both differences built inside `0x4b28ff0` | receives two already-computed differences |
| When it logs | `abci_minus_firewall` non-empty, or `firewall_minus_abci` has more than 6 entries | any non-empty difference |
| Extra pass | entries may be removed from `abci_minus_firewall` before the test | none |
| Repeats | at most once per `interval` seconds of wall-clock time; the first call always logs | "throttled tracing site", no rule given |
| Result | none used; the caller overwrites `rax` | `Err(FirewallDoesNotMatchValidators)` |
| Caller | `0x4524f70` (itself called from `0x4678d36`) | `0x28F6960` |
| Template text | starts with `firewall` | starts with `<` (the length byte) |

## Inference

- The `+0x8` dword is a wall-clock date field that is never 0 for a real
  time, so 0 marks "never logged".
- The 20-byte value and the extract pass probably remove this node's own
  entry or a configured exception from `abci_minus_firewall`. The predicate is
  not decoded.
- The level byte at `0x577b288 + 0x48` behaves like a lazily-initialised
  selector. Which values 1, 2, 15 and 17 stand for is not decoded.

## Unresolved

- The interval value and who writes the throttle state.
- What `0x45c3d20` collects (the lead calls it the computed validator IPs).
- The predicate of the extract pass.
- How `0x4524f70` relates to the seed `0x28f6960`.

## Controls

- `tests/test_firewall_mismatch_static.py` checks:
  - the models `logs` and `elapsed_seconds`;
  - the gate, the difference order, the log, the level gate and the caller;
  - regeneration of `records.json` and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - the `<= 6` bound, swapped difference operands and the tipping shift;
  - the 1e6 divisor;
  - the log template, the Location, the `Time Sub` template and the
    `raw_mdg.rs` path;
  - the elapsed and level RELATIVE slots;
  - removing the caller's `rax` overwrite.
- Both toolchains: the module passes with GNU binutils on `PATH` and with only
  LLVM; the tool itself uses neither.
