# RE-012: gossip collection count check and the exact scalar threshold

- Component/task: `node-runtime`, RE-012 bounded static research.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred
  reference implementation, labels or tests are copied. New work is independently
  authored under the repository MIT license; captured bytes retain upstream rights.
- Question: what follows the selected collection call if its count differs,
  and what exact raw-word threshold reaches numeric output `0x8000000000000038`?
- Status: original instruction/flag/layout observations; count, collection and
  container labels are inferences. No source-level peer policy or error name
  is established. No reconstruction gate changes.

## Reproduce

From the repository root with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-012-gossip-count-threshold-94/collect.py
```

Observed: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0. The collector uses
reviewed ELF/FDE parsers (hashes in `records.json`) and the installed Apple
LLVM static tools. Exact commands are retained in both text exports. Other
platforms require equivalent installed LLVM paths. Only static local reads
and packet writes occur: no target executable/instruction evaluator, network,
chain action, real fixture or model call runs.

The complete previously exported owner `0x4743490..0x4744152` is freshly
authenticated and linearly decoded: **3,266 bytes / 584 LLVM instruction rows**.
Actual CIE/FDE and unwind-index records agree with independent LLVM dwarfdump.
Every row must be contiguous, known and byte-identical to the input. The
new interpretation is confined to **177 bytes / 28 rows** in two selected
windows, plus provenance and direct-helper anchors. The full owner is context,
not new reconstruction credit or a whole-node coverage denominator.
Addresses are linked ELF VAs, file offsets are section-resolved, and ends are
exclusive. Only surplus trailing newlines in LLVM text are removed; there
are no operand/data masks, reduced analysis profiles or analysis timeouts.

## Count check and conditional diagnostic route

At `0x474395e`, the caller passes output address `&stack[0x170]` and input
descriptor `&stack[0x248]` to direct target `0x47c0ec0`. Its body and collection
contract remain opaque here. On ordinary return, `0x4743963` compares qword
`[rsp+0x180]` with current RBX. Call these C and M, respectively.

The earlier instructions load a word at entry RDX `+0x30`, save it at stack
`+0x1b0`, and reload that slot into RBX at `0x47438d0`. This is the local
provenance of the compared word. Identifying its runtime value with the entry
word assumes ordinary ABI preservation and no intervening alias mutation;
the guard relation below is defined on the actual post-call RBX regardless.

If C differs from M, JNE targets `0x4743bf4`. That block prepares diagnostic
arguments, references Location `node/src/gossip_config.rs:421:9`, and calls
through slot `0x576e978`. The unique RELATIVE records resolve the Location path
and slot target `0x143d010`, with original bytes in `records.json`. This is
not proof of the diagnostic helper's source type, logging/panic behavior or
normal return. **If that call returns normally**, the local fallthrough reaches
`0x4743c52`; if it does not return, no subsequent output store is established.

If C equals M, execution instead reaches the scalar threshold below. No call
lies inside that threshold's instruction corridor.

## Exact raw-word threshold

Let N be the u64 loaded from `[rsp+0x110]` at `0x4743979`, and M the current
RBX word. The instructions are:

```text
0x4743981  mov rcx,rax
0x4743984  shr rcx,63          ; high word of mathematical 2*N
0x4743988  add rax,rax         ; low 64 bits of 2*N
0x474398b  lea rdx,[rbx+2*rbx] ; low 64 bits of 3*M
0x474398f  cmp rax,rdx
0x4743992  sbb rcx,0
0x4743996  jae 0x4743c52
```

Writing W = `(3*M) mod 2^64`, the CMP borrow is 1 exactly when
`(2*N mod 2^64) < W`. The following SBB borrows exactly when the high word
`N>>63` is less than that borrow. JAE therefore reaches the numeric-tag block
exactly when the **wide-integer** relation is:

```text
2*N >= ((3*M) mod 2^64)
```

The double's high word is retained; the triple's high word is not retained.
Consequently a plain unbounded `2*N >= 3*M` relation is justified only under
an additional no-wrap bound such as `M <= floor(u64::MAX/3)`. No invariant
establishing the actual admissible M/N population is recovered here.

Examples below describe raw-word algebra, not native requests or reachable
runtime states:

| N | M | Numeric-tag branch |
| ---: | ---: | --- |
| 0 | 0 | Taken (equality) |
| 1 | 1 | Not taken (`2 < 3`) |
| 3 | 2 | Taken (equality) |
| 2 | 2 | Not taken (`4 < 6`) |
| `2^63` | any u64 | Taken (double has a high word) |
| 1 | `6148914691236517206` | Taken (`3*M mod 2^64 = 2`) |

The final raw example differs from the unbounded triple relation. This does
not establish a reachable overflow, unsafe configuration or vulnerability;
ordinary container/allocation invariants may rule out such values. They remain
unclosed rather than guessed. This packet records the exact machine-word rule
needed before a later source reconstruction assigns a meaningful domain.

If the threshold branch is not taken, the next instruction at `0x474399c`
loads qword `[current R14+0x28]` for a later path. The meaning of that pointer,
word, later allocation cap, iterator or peer-selection policy is not recovered.

## Numeric output and limitations

At `0x4743c52`, the code loads `0x8000000000000038`, reloads a pointer from
stack `+0x88` into R12, and stores the numeric word through R12. These are
ordered local instructions, not a claim about a named Rust `Result`, final
memory under arbitrary pointer aliasing, safe ownership, or successful return
after later cleanup. The count-mismatch path reaches this store only under
the diagnostic's normal-return condition; the threshold-taken corridor reaches
it directly. Both real branch targets are checked against owner boundaries.

The collector checks 19 instruction spans and the direct collection boundary.
Twenty real byte corruptions run through the same local operand validator,
bypassing the outer image/body hashes, and all reject. They are evidence
admission tests, not execution of mutated target instructions. A separate
289-pair finite arithmetic check compares the unsigned-borrow form with the
wide-integer relation over 17 explicit u64 values, including wrap boundaries.
It is a mathematical consistency check, not target behavior or an exhaustive
runtime-input test. All raw pairs/results are retained. Two collections
reproduce all generated evidence byte for byte (`validation.json`).

Before this packet, PR #1941 established the preceding seed construction and
PR #1954 the selected lookup/projection and comparison-return corridor; both
leave downstream policy open. Afterward the selected count/threshold routes
and numeric store have digest-bound explanations. `gossip-config-inventory-94`
previously inventories the Location without interpreting its predecessors.
The complete 598-open-PR inventory and exact address/scope searches found no
competing work on this guard. Prior exports/helper context earn no new coverage.

No Rust implementation, behavior comparison, complete CFG/helper closure,
accepted API/configuration population, peer policy, source-type recovery,
source/binary equivalence or component completion is claimed. Opaque collection,
diagnostic and cleanup effects, transitive aliases and exceptional paths remain
open. No imported evidence or progress gate changes.

Next question: close `0x47c0ec0`'s descriptor/output contract and the later
selection path so these raw C/M/N words can be assigned proved source-level
meanings and bounded domains.
