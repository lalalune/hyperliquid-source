# RE-001-node115-lu-loopcaller: the node #115 lu loop caller

- Component ID: RE-001-node115-lu-loopcaller
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded instructions, call targets,
  and stores; inference for the argument roles (count as splice budget,
  entry slot as accumulation point, return as spliced count), each
  grounded in the branch structure; unresolved for the fetched item,
  value compute, predicate, virtual call, completion protocol, the
  missing `endbr64`, chain-order observability, and the driver FDE
- Scope included and excluded: the single FDE `0x63b81b0..0x63b8517`
  (871 bytes) end to end, including its out-of-line blocks
  (contention, NULL-divert, fallback, stack-check). Excluded: the
  fetch, class-search, take, value, predicate, wake, give-back,
  release, completion, contention, and fallback callees; the
  single-shot caller FDE; the driver FDE — all cited by address only

## Reproduce

Working directory: the worktree at `~/workspace/hl-wt-calls233-115`
(branch `codex/re-004-calls233-115`, upstream main `8fd8db6`).

- `objdump -d --start-address=0x63b81b0 --stop-address=0x63b8517
  artifacts/node/115/hl-node` reproduces the full FDE disassembly.
- `readelf --debug-dump=frames artifacts/node/115/hl-node` gives the
  FDE bounds `pc=0x63b81b0..0x63b8517`; the following bytes
  `0x63b8517..0x63b851f` are `int3` padding and the next function
  starts with `endbr64` at `0x63b8520`.
- `python3 tools/node115_lu_loopcaller.py` (exit 0) re-checks every
  exhibit byte, strict count, key store/call bytes, branch-target
  containment, census, disjointness, and MANIFEST coverage.
- `python3 -m unittest tests.test_node115_lu_loopcaller` (10/10)
  re-generates every exhibit from the binary and applies the tamper
  control.
- No execution of the node binary at any point; no network use
  beyond the upstream fetch that confirmed `8fd8db6` unmoved.
- Environment: binutils objdump/readelf as installed in the VM;
  `git-lfs` 3.4.1 present at session start (no restore needed);
  worktree submodules were uninitialised on first `make verify`
  (pinned reference `upstream/node/pub_key.asc`) and were fixed with
  the standard `git submodule update --init --recursive --force`
  plus `git lfs pull` before the green runs.

## Evidence

- Coordinate system: `.text` file offset = VA − 0x1000 (verified on
  every exhibit byte and every call rel32 in this packet).
- Entry bytes at `0x63b81b0` are `41 57 41 56` (`push %r15; push
  %r14`) — the FDE has no `endbr64`. The preceding function
  `0x63b8160..0x63b81ab` (`endbr64`, one call to `0x63b7ef0`,
  `ret`) is a separate FDE; it cannot contain the class-search
  call site `0x63b827f`. This corrects packet #230's first-caller
  FDE range (argument setup and NULL test were correct).
- 6 exhibits, 475 bytes, 114 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `lc_entry` | `0x63b81b0..0x63b8212` | 98 | 24 | Entry, arg saves, trylock |
| `lc_loop` | `0x63b8250..0x63b8290` | 64 | 15 | Fetch, NULL test, class-search call |
| `lc_take` | `0x63b8290..0x63b82c3` | 51 | 12 | Take call, stamp, value compute |
| `lc_build` | `0x63b82c3..0x63b8335` | 114 | 24 | Entry build, predicate call |
| `lc_splice` | `0x63b83b1..0x63b840a` | 89 | 22 | Splice, loop check, exit jump |
| `lc_ret` | `0x63b849a..0x63b84d5` | 59 | 17 | Byte set, unlock, canary, return |

- Single `ret` at `0x63b84d4`; 17 direct branch targets, all inside
  the FDE (verified by objdump scan, not by hand).
- Census: direct `E8` call sites to `0x63b81b0`: 5 — `0x63b8baf`
  and `0x63b8c59` (single-shot caller FDE, #232), `0x63b8e1a`,
  `0x63b8e95`, `0x63b8f4d` (driver FDE `0x63b8d90..0x63b8fd1`,
  cited by address only). Direct `E9`: 0. Rip-relative `LEA`: 0.
  `.rela.dyn` addends equal to `0x63b81b0`: 0 of 60,723 entries
  (section size `0x163cc8` / 24).
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#232 and no other contributor's topic, addresses, or tables;
  the single-shot caller, the driver FDE, and all helpers are cited
  by address, not claimed here.
- `.bss` contents are runtime-filled and not readable from the file;
  nothing here depends on them.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet; it is an evidence packet only. The decoded semantics
(count-bounded splice loop returning the spliced count) are stated
as the target behaviour a future implementation must match.

## Results and limitations

- Decoded: full loop structure, argument roles, per-iteration
  consumption sequence, splice mechanics, early-exit paths and
  their effect on the return value, epilogue and completion
  protocol, and both driver call patterns (verified by address:
  #232's second phase and the driver FDE's accumulation).
- Not decoded: the callees listed under scope-excluded; the driver
  FDE's internals beyond its three call sites and accumulation
  shape; the intermediate `0x63b85f0` call between driver rounds.
- Next question: decode the driver FDE `0x63b8d90..0x63b8fd1` end
  to end — how it accumulates the loop caller's returns across its
  three call sites, what its intermediate `0x63b85f0` call does
  between rounds, and when it stops.
