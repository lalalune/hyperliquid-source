# RE-008: node #115 move_token 0x5580d10 call census (stage 101)

- Component ID: exchange. Question: #6213 (stage 100) bound the move_token legs and showed that 0x5580d10 returns tag 0x1a2 before either leg when r8 equals stack argument 0 and either r8 is 0 or r9 equals stack argument 1, and that the 0x55817e0 path always takes that exit. It left open which of the other callers can reach the legs.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6212 and #6213. It does not depend on their files.
- Claim status: instruction bytes, call targets, FDE extents and the class derived from pinned argument setters are observations. "Move", "early exit" and argument meanings are inferred labels. The binary was not executed.
- Scope included: the early-exit compare in 0x5580d10; for each of its 51 direct calls, the last r8/r9 setter and the stack-argument 0/1 store or push before the call. Scope excluded: values held in registers or memory at the call (traced no further than the setter), the legs (#6213) and the enclosing functions' purpose.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/move_token_callers_115.py --check
python3 -m unittest tests.test_move_token_callers_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the early-exit rule

0x5580d10 pushes six registers (0x30 bytes) and subtracts 0x178, so stack argument 0 is `[rsp+0x1b0]` and argument 1 is `[rsp+0x1b8]`. It keeps r8 in r15 and r9 in rbp (`0x5580d21`, `0x5580d24`). `0x5580d7e` `cmp r15, [rsp+0x1b0]`; `jne` goes to the legs; `test r15, r15` / `je 0x558136b`; `cmp rbp, [rsp+0x1b8]` / `je 0x558136b`. 0x558136b is the tag 0x1a2 return bound in #6213.

## Evidence 2: per-site setters and class

For each call the tool pins the last instruction before the call that sets r8 (`mov r8d, imm32`, `xor r8d, r8d`, `sete r8b`, or a register/memory move), r9 where present, and the store or push that supplies arguments 0 and 1 (`mov qword [rsp], imm32`, `mov [rsp], reg`, `movups/movdqu [rsp+0x8], xmm`, or `push`, where the last push is argument 0). The class is derived from those bytes:

- **early-exit**: r8 and argument 0 are both the constant 0.
- **can-move**: r8 and argument 0 are differing constants, or r8 is a `sete` result and argument 0 is the constant 1.
- **unresolved**: r8 or argument 0 is a register or memory value at the call.

| Site | Function | r8 | arg 0 | Class |
|---|---|---|---|---|
| `0x54d72f2` | `0x54d57b0` | 1 | 0 | can-move |
| `0x54d760a` | `0x54d57b0` | 1 | 0 | can-move |
| `0x54d78f5` | `0x54d57b0` | sete | 1 | can-move |
| `0x54d7a22` | `0x54d57b0` | 1 | value | unresolved |
| `0x556ae0f` | `0x556ab20` | 1 | 0 | can-move |
| `0x556b0c2` | `0x556ab20` | sete | 1 | can-move |
| `0x556b1f5` | `0x556ab20` | 1 | value | unresolved |
| `0x556b67d` | `0x556b3a0` | 1 | 0 | can-move |
| `0x556b929` | `0x556b3a0` | sete | 1 | can-move |
| `0x556ba56` | `0x556b3a0` | 1 | value | unresolved |
| `0x55700de` | `0x556fdf0` | 1 | 0 | can-move |
| `0x557038d` | `0x556fdf0` | sete | 1 | can-move |
| `0x55704bd` | `0x556fdf0` | 1 | value | unresolved |
| `0x557c492` | `0x557ac40` | 0 | 0 | early-exit |
| `0x557c5c3` | `0x557ac40` | 0 | 0 | early-exit |
| `0x5581c1c` | `0x55817e0` | 0 | value | early-exit (via #6213 caller) |
| `0x55825d5` | `0x5582180` | 1 | 0 | can-move |
| `0x558314a` | `0x5582180` | 0 | 1 | can-move |
| `0x5584a5c` | `0x5582180` | 0 | 1 | can-move |
| `0x55886ac` | `0x5588670` | value | 0 | unresolved |
| `0x5588e9a` | `0x5588d90` | 0 | value | unresolved |
| `0x558923f` | `0x55890d0` | 1 | 0 | can-move |
| `0x558aad2` | `0x558a600` | 1 | value | unresolved |
| `0x558ae39` | `0x558a600` | value | 0 | unresolved |
| `0x558af61` | `0x558a600` | 1 | value | unresolved |
| `0x558d886` | `0x558d4c0` | value | 0 | unresolved |
| `0x558dba5` | `0x558d4c0` | sete | 1 | can-move |
| `0x558de33` | `0x558d4c0` | 1 | value | unresolved |
| `0x558ea04` | `0x558e680` | sete | 1 | can-move |
| `0x558eb2f` | `0x558e680` | 1 | value | unresolved |
| `0x558ebe7` | `0x558e680` | 1 | 0 | can-move |
| `0x558fc6e` | `0x558f9e0` | 1 | 0 | can-move |
| `0x558ffd8` | `0x558fe10` | value | 0 | unresolved |
| `0x559013e` | `0x558fe10` | sete | 1 | can-move |
| `0x559021b` | `0x558fe10` | 1 | value | unresolved |
| `0x559071c` | `0x5590380` | value | 0 | unresolved |
| `0x559088a` | `0x5590380` | sete | 1 | can-move |
| `0x5590a4a` | `0x5590380` | 1 | value | unresolved |
| `0x5590e8b` | `0x5590bb0` | sete | 1 | can-move |
| `0x5590f71` | `0x5590bb0` | 1 | value | unresolved |
| `0x5591020` | `0x5590bb0` | value | 0 | unresolved |
| `0x55921fa` | `0x5591ce0` | sete | 1 | can-move |
| `0x55923cd` | `0x5591ce0` | 1 | value | unresolved |
| `0x5592481` | `0x5591ce0` | value | 0 | unresolved |
| `0x559349b` | `0x55931c0` | sete | 1 | can-move |
| `0x5593581` | `0x55931c0` | 1 | value | unresolved |
| `0x5593630` | `0x55931c0` | value | 0 | unresolved |
| `0x5593b3a` | `0x5593810` | sete | 1 | can-move |
| `0x5593c22` | `0x5593810` | 1 | value | unresolved |
| `0x5593ce5` | `0x5593810` | value | 0 | unresolved |
| `0x560abd9` | `0x560a550` | 0 | 0 | early-exit |

The site `0x5581c1c` is classed by #6213, which binds argument 0 (r12) to the caller's rcx = 0 on the only path into 0x55817e0.

## Results and limitations

- Totals: 23 can-move, 24 unresolved, 3 early-exit, 1 early-exit via #6213. Functions: 21.
- The two calls in `0x557ac40` (`0x557c492`, `0x557c5c3`) and the one in `0x560a550` (`0x560abd9`) pass r8 = 0 and argument 0 = 0, so they never reach a leg; on those paths 0x5580d10 only increments Locus ctr and the inner counter it updates on entry.
- 'Can-move' means at least one setter value skips the early exit; whether a balance changes also depends on the amount and the leg checks in #6213.
- Limits: the 24 unresolved sites need the register or memory value traced further; the tool does not follow control flow between the setter and the call (it only requires the setter to sit within 0x120 bytes before it); argument 1 is pinned but not used in the class.
- Next lead: trace argument 0 at the 14 sites that store `rax` with an xmm pair at `[rsp+0x8]` (the paired form), which look like two (index, key) endpoints compared for equality.
