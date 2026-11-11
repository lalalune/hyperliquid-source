# RE-011: node #115 small-input ordering in the fee-history reward-input path

- Task: RE-011 (fee-history reward inputs). One bounded node #115 evidence packet.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source / base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: RE-011 fee-history leaves the reward-input ordering unresolved. On the observed small-input path, how does the helper reached by the direct call at `0x2a2121d` order the 32-byte records it walks?
- Result (bounded): inside FDE `0009c51c` the window `0x26ce540..0x26ce5ec` walks 32-byte records and compares them as unsigned 128-bit pairs (low qword by CMP, high qword by SBB) with unsigned JAE/JB branches before shifting. Equal compared pairs do not take the shift path.

## Exact scope

| Role | Half-open VA range | Bytes | Identity |
| --- | --- | ---: | --- |
| helper body, complete FDE `0009c51c` | `0x26ce540..0x26ce5ec` | 172 | window SHA-256 `a4ac8ddf95b3cbfb5ed4acb30ac773f7bbd95bdc6c050bee03a2ad5e9a96f693` |
| caller call site | `0x2a2121d..0x2a21222` | 5 | bytes `e81ed3caff` |

The FDE limits `pc_start=0x26ce540` and `pc_end=0x26ce5ec` are the recorded readelf decode for index `0009c51c` on this target. The checker compares those recorded values with the window constants and does not re-parse `.eh_frame`. This packet contains no `frames.txt` file.

## Observed bytes

Decode of the authenticated window, read in place from `artifacts/node/115/hl-node` (never executed, never copied):

```
0x26ce540  48 8d 42 ff          lea    rax,[rdx-1]
0x26ce544  48 39 f0             cmp    rax,rsi
0x26ce547  0f 83 9d 00 00 00    jae    0x26ce5ea
0x26ce54d  48 39 f2             cmp    rdx,rsi
0x26ce550  0f 84 93 00 00 00    je     0x26ce5e9
0x26ce556  53                   push   rbx
0x26ce557  48 c1 e6 05          shl    rsi,0x5
0x26ce55b  48 01 fe             add    rsi,rdi
0x26ce55e  48 c1 e2 05          shl    rdx,0x5
0x26ce562  48 8d 04 17          lea    rax,[rdi+rdx*1]
0x26ce566  eb 23                jmp    0x26ce58b
0x26ce568  0f 1f 84 00 00 00 00 00  nop
0x26ce570  49 89 fa             mov    r10,rdi
0x26ce573  49 89 0a             mov    [r10],rcx
0x26ce576  4d 89 42 08          mov    [r10+0x8],r8
0x26ce57a  4d 89 4a 10          mov    [r10+0x10],r9
0x26ce57e  48 83 c0 20          add    rax,0x20
0x26ce582  48 83 c2 20          add    rdx,0x20
0x26ce586  48 39 f0             cmp    rax,rsi
0x26ce589  74 5d                je     0x26ce5e8
0x26ce58b  48 8b 08             mov    rcx,[rax]
0x26ce58e  4c 8b 40 08          mov    r8,[rax+0x8]
0x26ce592  48 3b 48 e0          cmp    rcx,[rax-0x20]
0x26ce596  4d 89 c1             mov    r9,r8
0x26ce599  4c 1b 48 e8          sbb    r9,[rax-0x18]
0x26ce59d  73 df                jae    0x26ce57e
0x26ce59f  4c 8b 48 10          mov    r9,[rax+0x10]
0x26ce5a3  49 89 d3             mov    r11,rdx
0x26ce5a6  66 2e 0f 1f 84 00 00 00 00 00  nop
0x26ce5b0  42 0f 28 44 1f e0    movaps xmm0,[rdi+r11*1-0x20]
0x26ce5b6  42 0f 28 4c 1f f0    movaps xmm1,[rdi+r11*1-0x10]
0x26ce5bc  42 0f 29 4c 1f 10    movaps [rdi+r11*1+0x10],xmm1
0x26ce5c2  42 0f 29 04 1f       movaps [rdi+r11*1],xmm0
0x26ce5c7  49 83 fb 20          cmp    r11,0x20
0x26ce5cb  74 a3                je     0x26ce570
0x26ce5cd  4d 8d 53 e0          lea    r10,[r11-0x20]
0x26ce5d1  4a 3b 4c 1f c0       cmp    rcx,[rdi+r11*1-0x40]
0x26ce5d6  4c 89 c3             mov    rbx,r8
0x26ce5d9  4a 1b 5c 1f c8       sbb    rbx,[rdi+r11*1-0x38]
0x26ce5de  4d 89 d3             mov    r11,r10
0x26ce5e1  72 cd                jb     0x26ce5b0
0x26ce5e3  49 01 fa             add    r10,rdi
0x26ce5e6  eb 8b                jmp    0x26ce573
0x26ce5e8  5b                   pop    rbx
0x26ce5e9  c3                   ret
0x26ce5ea  0f 0b                ud2
```

## What the bytes establish

1. Stride. `0x26ce557` `48c1e605` and `0x26ce55e` `48c1e205` are `shl rsi,0x5` and `shl rdx,0x5`: a record count scaled by 32. Every advance is `add rax,0x20` and `add rdx,0x20`, so the walked stride is 32 bytes.
2. Outer comparison. `0x26ce592` `483b48e0` is `cmp rcx,[rax-0x20]`; `0x26ce596` `4d89c1` copies the current high qword (`r8` from `[rax+0x8]`) into `r9`; `0x26ce599` `4c1b48e8` is `sbb r9,[rax-0x18]`; `0x26ce59d` `73df` is `jae 0x26ce57e`, an unsigned backward branch to the advance step. Low qword by CMP, high qword by SBB: an unsigned 128-bit compare.
3. Inner comparison. `0x26ce5d1` is the complete 5-byte instruction `4a3b4c1fc0` (`cmp rcx,[rdi+r11*1-0x40]`, REX.W plus REX.X, opcode `3b`, ModRM `4c`, SIB `1f`, disp8 `c0`); `0x26ce5d6` `4c89c3` is `mov rbx,r8`; `0x26ce5d9` is the complete 5-byte instruction `4a1b5c1fc8` (`sbb rbx,[rdi+r11*1-0x38]`); `0x26ce5e1` `72cd` is `jb 0x26ce5b0`. Earlier 6-byte and 4-byte strings at these two sites were expanded to these complete instructions.
4. Loop step. `0x26ce586` `4839f0745d` is `cmp rax,rsi` followed by `je 0x26ce5e8`: a register compare and a conditional branch, a loop step, not a memory read.
5. Movement widths. The first `movaps` at `0x26ce5b0` is a 6-byte instruction (`420f28441fe0`), so the second `movaps` begins at `0x26ce5b6`, not `0x26ce5b7`. The vector block `0x26ce5b0..0x26ce5c7` copies 32 bytes with two 16-byte `movaps` loads and two `movaps` stores. The held-record stores at `0x26ce573` (`49890a`), `0x26ce576` (`4d894208`) and `0x26ce57a` (`4d894a10`) write record offsets 0, 8 and 16, 24 bytes in total.
6. Entry contract. `0x26ce540` `488d42ff` is `lea rax,[rdx-1]`; `0x26ce544` compares it with `rsi` and branches with `jae` to `0x26ce5ea`, whose bytes are `0f0b`; `0x26ce54d` compares `rdx` with `rsi` and branches with `je` to `0x26ce5e9`, whose byte is `c3`. The observed entry contract is therefore unsigned `1 <= rdx <= rsi`. This packet makes no claim about what a length-zero invocation returns.
7. Call site. `0x2a2121d` `e81ed3caff` is a direct relative call; its displacement `0xffcad31e` resolves to `0x26ce540`.

## Inferences, kept apart from the byte observations

- On the observed small-input path the window behaves like an ascending insertion step over 32-byte records: a record advances when the unsigned 128-bit compare of the two compared qwords sets no borrow, and otherwise the shift path moves records one 32-byte slot.
- Because equality clears the carry into `jae`, equal compared pairs do not take the shift path. `evidence.json` records that consequence for synthetic input in an independent stable-insertion model.
- These are inferences from bytes. The target was not executed and no behaviour outside this window is claimed.

## Independent model and corruption controls

`tools/foundation_small_input_ordering.py` reads the pinned target in place and re-derives the byte-backed values: the call displacement and its target, the window length and digest, the comparison and back-edge instruction bytes with their branch targets, and both stride decodes. It compares those derived values with `evidence.json`. The FDE pc limits `0x26ce540..0x26ce5ec` and the 24/32-byte movement widths are recorded values compared against fixed constants in the checker; they are not derived from the target and the checker does not parse `.eh_frame`. `tests/test_foundation_small_input_ordering.py` runs the checker. The checker requires the pinned digest and size, the call-site displacement, the window digest, both complete comparison instructions, the branch targets and both 32-byte stride decodes, then rejects mutated CMP/SBB/JAE opcodes, a mutated stride immediate, a mutated shift amount, a mutated call displacement and window-digest drift. The committed test also rejects a drifted comparison byte, a drifted stride byte and a drifted model relation, and exercises the real derived values (`jae` target `0x26ce57e`, back edge `0x26ce5b0`, stride 32).

The model section of `evidence.json` is a model, not target execution: unsigned 128-bit comparison on boundary and tie pairs, plus stable insertion order over synthetic labelled records. Equal keys keep their input order in that model; that is a property of the model and of the observed non-shifting equality branch, not a measured run of the target.

## Reproduce

```
sh
python3 test-results/slop-workbench/packet-6ae71fcce192.py
python3 -B tools/foundation_small_input_ordering.py
python3 -m unittest discover -s tests -p test_foundation_small_input_ordering.py -v
make doctor
make verify catalogue-check
make reproduce
```

`test-results/slop-workbench/packet-6ae71fcce192.py` is a PR-supplied reproduction file, not a committed repository file. Only host-recorded results are claimed. The scratch verifier prints the derived window, call site, comparison, back-edge and stride facts before it asserts them, then runs the committed checker on the saved packet; while this README was absent it failed on the missing packet file, and the host reruns it now that every packet file exists. No result for `make doctor`, `make verify catalogue-check`, `make reproduce` or the committed test is claimed here.

## Limits

- Static byte evidence only. The target was read in place and never executed or copied; no runtime behaviour is measured.
- The FDE limits are recorded readelf values compared against window constants; the checker does not parse `.eh_frame`, and no `frames.txt` file exists in this packet.
- The window is one complete FDE body. Other callers of `0x26ce540` are not enumerated, so this is not a complete xref census.
- Not claimed: preservation of the fourth qword of a 32-byte record (held stores cover 24 bytes while vector moves span 32); the meaning of the branch target at `0x26ce547` (bytes `0f0b`); the identity of any external method; a complete reward or fee algorithm; the result of a length-zero helper invocation; any whole-component gate.

## Next question

Which record fields feed the outer comparison and the inner comparison from the caller at `0x2a2121d`, and does that caller pass unchanged fee-history records into this helper?
