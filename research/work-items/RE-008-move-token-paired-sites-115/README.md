# RE-008: node #115 move_token paired call sites (stage 102)

- Component ID: exchange. Question: #6214 (stage 101) classed the 51 direct calls to move_token `0x5580d10` and left 24 unresolved, because r8 or stack argument 0 was a register or memory value rather than a constant. This packet binds the argument setters of those 24 sites and states, for each, exactly when the early exit is taken.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6213 and #6214. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, call targets, the relocation of slot `0x64e7b20`, FDE extents and the three argument shapes are observations. "Source", "destination", "kind", "spot", "clearinghouse" and "collateral" are inferred labels. The binary was not executed.
- Scope included: the 0x60 bytes before each of the 24 calls (0xc0 bytes for the index register). Scope excluded: values in registers or memory before those windows, what `[cls_elem+0x58]` holds, and the enclosing functions' purpose.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/move_token_paired_sites_115.py --check
python3 -m unittest tests.test_move_token_paired_sites_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the early-exit rule (from #6214, re-pinned)

`0x5580d7e` `cmp r15, [rsp+0x1b0]` / `jne`; `test r15, r15` / `je 0x558136b`; `cmp rbp, [rsp+0x1b8]` / `je 0x558136b`. r15 holds r8 and rbp holds r9. Caller `[rsp]` is stack argument 0 and `[rsp+0x8]` is argument 1. So the legs are skipped when `r8 == arg0` and either `r8 == 0` or `r9 == arg1`.

## Evidence 2: three argument shapes cover all 24 sites

| Shape | Sites | Setters (in order before the call) | Early exit taken when |
|---|---|---|---|
| P | 14 | `mov rcx,[X+0x58]`; `xor eax,eax`; `test rcx,rcx`; `sete al`; zeroed xmm (`xorps`/`pxor`) stored at `[rsp+0x8]`; `mov [rsp],rax`; `mov r8d,1`; `mov r9,<reg>` | `[X+0x58] == 0` and `r9 == 0` |
| Z | 9 | `mov qword [rsp],0` with no later `[rsp]` store; `mov r8,<reg or memory>` | `r8 == 0` |
| S | 1 (`0x5588e9a`) | `xor r8d,r8d`; `push 0`; `push r14`; `push rbx` | `rbx == 0` |

For P, arg0 is 1 exactly when `[X+0x58]` is 0, and arg1 is 0. With r8 = 1 the exit therefore needs arg0 = 1 and r9 = 0. For Z, arg0 is 0, so the first compare matches only when r8 = 0, and then `test r15,r15` exits without reading arg1. For S, r8 = 0, so the exit needs arg0 (rbx) = 0.

## Evidence 3: in every P site, r9 is the Locus cls index

X is a 0x510-byte Locus `cls` element (#6207). The tool finds the register that selects it and checks that r9 carries the same value:

- 9 sites call slot `0x64e7b20` (relocated to `0x446b370`) with that register in rsi, and r9 is the same register;
- 2 sites (`0x5590f71`, `0x5593581`) copy it first (`mov rbx,r14` at `0x5590f39` / `0x5593549`);
- 2 sites (`0x558aad2`, `0x558af61`) use `imul <dst>,<reg>,0x510` on the same register;
- 1 site (`0x54d7a22`) bounds-checks it with `cmp rbp,[rax+0x7d0]` (Locus cls length).

So 14 of 14 P sites pass the clearinghouse index as r9.

## Interpretation (inference)

The early-exit rule reads like an equality test on two `(kind, id)` values: `(r8, r9)` and `(arg0, arg1)`, where kind 0 carries no id. Under that reading:

- P moves from clearinghouse `q` (kind 1, id q) to clearinghouse 0 when the element's `+0x58` word is 0, and to kind 0 otherwise; it is a no-op only for `q = 0` with `+0x58 == 0`.
- Z moves from `(r8, r9)` to kind 0; it is a no-op only when the source kind is already 0.
- S moves from kind 0 to `(rbx, r14)`; it is a no-op only when the destination kind is 0.

Kind 0 matching the `to_spot` / `from_spot` strings of #6212 suggests kind 0 = spot and kind 1 = a clearinghouse.

## Totals after this stage

| Class | Sites |
|---|---|
| can-move (stage 101) | 23 |
| early-exit (stage 101, incl. #6213) | 4 |
| conditional P / Z / S (this stage) | 14 / 9 / 1 |
| unresolved | 0 |

## Implementation and comparison

The tool pins the early-exit bytes, the slot relocation and the 51-call census, then decodes each site's setters from bytes and asserts the expected shape for all 24. Tests mutate one byte in a copy of the image (compare offset, `sete`, the r8 constant, the `+0x58` displacement, the xmm store offset, the zero store, the `push 0`, a call target) and expect rejection (8 mutation tests).

## Limits

- What `[cls_elem+0x58]` holds, and the values of r8 / rbx at Z and S sites, are not traced beyond the setter.
- The `(kind, id)` reading and the spot / clearinghouse names are inferences.
- The enclosing functions (14 of them) are not named.
- Next lead: what writes the cls element `+0x58` word, which decides whether a clearinghouse's tokens move to clearinghouse 0 or to spot.
