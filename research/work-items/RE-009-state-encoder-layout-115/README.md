# RE-009: Node #115 state-encoder dispatch layout

- Component/task: ABCI / RE-009, state export.
- Target: Linux x86-64 Node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes.
- Reference/base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: static observations and explicitly bounded inferences; **no gate change**.
- New code and documentation are independently authored under the root MIT license.
  Captured artifacts retain their existing provenance/rights. No inferred
  can1357 source was consulted or copied.

## Question and prior gap

What is the complete ordered field-dispatch contract of the selected state
serializer, including native input operands and its first-error exit?

The base [state-export packet](../RE-009-abci-state-export-115/README.md)
retains 27 fixed-pattern name candidates and ten aligned field operands, while
the [snapshot-handoff packet](../RE-017-state-snapshot-handoff-115/README.md)
establishes the selected owner/caller and exchange/locus/ctx prefix.
Those facts and previously retained bytes are context, not new reconstruction
credit. Neither packet supplies this owner's complete 75-dispatch inventory.
The new result is the ordered, target-bound mapping below, with every dispatch
paired to its literal, native operand instructions, callee and result guard.
This is research toward a compatible state codec; it is not a runtime bug fix
or an independently implemented codec.

## Reproduce

Materialize the repository's pinned inputs using its normal approved setup.
Python 3.12.1 and Capstone **5.0.7** produced the retained evidence; GNU
objdump/readelf **2.47** supply independent partitions and unwind extents.
The operator's directory was named capstone-5.0.9; the imported module actually
reported 5.0.7. Versions here report the module, not the directory label.

From the repository root:

```sh
python3 -B research/work-items/RE-009-state-encoder-layout-115/extract.py \
  --check research/work-items/RE-009-state-encoder-layout-115/field-layout.json
python3 -B research/work-items/RE-009-state-encoder-layout-115/validate_contexts.py \
  --objdump objdump --readelf readelf
python3 -B -m unittest discover -s tests \
  -p test_node115_state_encoder_layout.py -v
make doctor
make verify test catalogue-check
make reproduce
```

The second command invokes only GNU analysis tools, never the captured artifact.
It rewrites the selected GNU transcripts and static-validation.json with observed
tool versions. Selected text transcripts use canonical LF for repository storage;
instruction bytes, operands and frame extents are unchanged. The hash of complete
raw readelf stdout is retained separately with its original line endings.
The extractor validates the
**entire** target size/hash before parsing. It uses actual .eh_frame FDEs and
file-backed PT_LOAD mappings; no address rebasing or normalization masks.
A local Windows run used explicit D Python/GNU paths and native Git Bash under
a bounded Windows Job supervisor, with D temporary/cache/output paths.
No captured execution, instruction emulation, provider call or chain access
was performed. Required repository results and the exact submitted source
head are reported separately in the PR; static packet checks alone do not
establish full repository success.

## Observations

### Root and scopes

The owner FDE is `0x5480950..0x548168c`, file offset `0x547f950`,
3,388 bytes, SHA-256
`9787b4fea4b5bf19ed892ab95747cf8d7a20cda44177dd6743413e0fdb100697`.
Its 756 instructions decode completely. These are unwind-described extents,
not a claim about original source-function boundaries.

Entry saves rdx as writer r14, rsi as r15 and rdi as result owner rbx.
At `0x54809c1`, it loads r15 from [r15]. All table operands refer to that
loaded root, not directly to the entry pointer-to-pointer. r15 remains that
root until the final add0x3908.

There are 93 direct calls: six alternative container-header sites, twelve
explicit key-writer sites and **75 value-dispatch sites**. Header counts in
instruction order are 1,1,59,59,17,17. The first 17 value calls are the locus
members; the next 58 are exchange siblings. The exchange count is therefore
the locus aggregate plus58 siblings, rather than75 direct exchange members.
Names, including `uaR` and repeated `msc` in different scopes, are preserved
byte for byte. Abbreviations are not expanded into invented type names.

### Native field order

The table's inputs are instructions at the outer call site, not validated
Rust types, object extents, ownership, optionality or wire widths.
field-layout.json additionally retains literal VAs/file offsets/exact bytes,
full native operands and every result branch.

| # | Scope / exact key | Outer call -> callee | Native input instruction(s) |
| ---: | --- | --- | --- |
| 1 | `exchange.locus.ctx` | `0x5480ac7 -> 0x4d93030` | `root passed in rsi` |
| 2 | `exchange.locus.cls` | `0x5480b17 -> 0x52f8530` | `lea r8, [r15 + 0x7c0]` |
| 3 | `exchange.locus.scl` | `0x5480b5b -> 0x5aefeb0` | `lea rsi, [r15 + 0x80]` |
| 4 | `exchange.locus.ftr` | `0x5480b7a -> 0x56795d0` | `lea rdx, [r15 + 0x7d8]` |
| 5 | `exchange.locus.ust` | `0x5480bbe -> 0x52b2230` | `lea rdx, [r15 + 0x968]` |
| 6 | `exchange.locus.chn` | `0x5480bde -> 0x56763f0` | `movzx edx, byte ptr [r15 + 0xb9a]` |
| 7 | `exchange.locus.pdl` | `0x5480c0a -> 0x56783a0` | `movzx r8d, byte ptr [r15 + 0xb98]` |
| 8 | `exchange.locus.uaR` | `0x5480c29 -> 0x5678ae0` | `lea rdx, [r15 + 0x9f8]` |
| 9 | `exchange.locus.blp` | `0x5480c48 -> 0x5674790` | `lea rdx, [r15 + 0x670]` |
| 10 | `exchange.locus.qus` | `0x5480c73 -> 0x5677400` | `lea r8, [r15 + 0xb78]` |
| 11 | `exchange.locus.ctr` | `0x5480c92 -> 0x5679120` | `lea rdx, [r15 + 0xa78]` |
| 12 | `exchange.locus.uac` | `0x5480cb1 -> 0x5678c70` | `lea rdx, [r15 + 0x9b0]` |
| 13 | `exchange.locus.vlt` | `0x5480cd0 -> 0x5673e00` | `lea rdx, [r15 + 0xa18]` |
| 14 | `exchange.locus.hcm` | `0x5480cf0 -> 0x56764b0` | `movzx edx, byte ptr [r15 + 0xb99]` |
| 15 | `exchange.locus.pmu` | `0x5480d1b -> 0x56736b0` | `mov r8, qword ptr [r15 + 0xb90]` |
| 16 | `exchange.locus.msc` | `0x5480d3a -> 0x5677a50` | `lea rdx, [r15 + 0xa38]` |
| 17 | `exchange.locus.aux` | `0x5480d52 -> 0x5673860` | `no outer source load` |
| 18 | `exchange.perp_dexs` | `0x5480da2 -> 0x52fa060` | `lea r8, [r15 + 0x3ac0]` |
| 19 | `exchange.spot_books` | `0x5480df2 -> 0x52f2950` | `lea r8, [r15 + 0x3ad8]` |
| 20 | `exchange.agent_tracker` | `0x5480e36 -> 0x4d6fce0` | `lea rsi, [r15 + 0x3af0]` |
| 21 | `exchange.funding_distribute_guard` | `0x5480e7a -> 0x5617020` | `lea rsi, [r15 + 0x4158]` |
| 22 | `exchange.funding_update_guard` | `0x5480ea5 -> 0x56781f0` | `lea r8, [r15 + 0x4168]` |
| 23 | `exchange.sub_account_tracker` | `0x5480ec4 -> 0x5677f60` | `lea rdx, [r15 + 0x3c58]` |
| 24 | `exchange.allowed_liquidators` | `0x5480eef -> 0x5677400` | `lea r8, [r15 + 0x41e8]` |
| 25 | `exchange.bridge2` | `0x5480f0e -> 0x56782b0` | `lea rdx, [r15 + 0xba0]` |
| 26 | `exchange.staking` | `0x5480f2d -> 0x5678250` | `lea rdx, [r15 + 0x3f08]` |
| 27 | `exchange.c_staking` | `0x5480f4c -> 0x56751e0` | `lea rdx, [r15 + 0xd88]` |
| 28 | `exchange.funding_err_dur_guard` | `0x5480f6b -> 0x5673740` | `lea rdx, [r15 + 0x4200]` |
| 29 | `exchange.max_order_distance_from_anchor` | `0x5480f98 -> 0x5678170` | `movq xmm0, qword ptr [r15 + 0x4220]` |
| 30 | `exchange.scheduled_freeze_height` | `0x5480fca -> 0x5675090` | `mov r8, qword ptr [r15 + 0x10e8]; mov r9, qword ptr [r15 + 0x10f0]` |
| 31 | `exchange.cancel_aggressive_orders_at_open_interest_cap_guard` | `0x5480ff5 -> 0x56781f0` | `lea r8, [r15 + 0x4178]` |
| 32 | `exchange.last_hlp_cancel_time` | `0x5481020 -> 0x5676bd0` | `lea r8, [r15 + 0x4288]` |
| 33 | `exchange.post_only_until_time` | `0x548104b -> 0x5676bd0` | `lea r8, [r15 + 0x4294]` |
| 34 | `exchange.post_only_until_height` | `0x5481071 -> 0x56771f0` | `mov rcx, qword ptr [r15 + 0x4228]` |
| 35 | `exchange.spot_twap_tracker` | `0x5481090 -> 0x5673650` | `lea rdx, [r15 + 0x3ce8]` |
| 36 | `exchange.user_to_display_name` | `0x54810af -> 0x56761a0` | `lea rdx, [r15 + 0x3f88]` |
| 37 | `exchange.book_empty_user_states_pruning_guard` | `0x54810da -> 0x56781f0` | `lea r8, [r15 + 0x4188]` |
| 38 | `exchange.user_to_scheduled_cancel` | `0x54810f9 -> 0x5673cd0` | `lea rdx, [r15 + 0x3fa8]` |
| 39 | `exchange.hyperliquidity` | `0x5481118 -> 0x5677460` | `lea rdx, [r15 + 0x3fc8]` |
| 40 | `exchange.spot_disabled` | `0x5481144 -> 0x56783a0` | `movzx r8d, byte ptr [r15 + 0x42ac]` |
| 41 | `exchange.prune_agent_idx` | `0x548116f -> 0x56736b0` | `mov r8, qword ptr [r15 + 0x4230]` |
| 42 | `exchange.max_hlp_withdraw_fraction_per_day` | `0x548119c -> 0x5678170` | `movq xmm0, qword ptr [r15 + 0x4238]` |
| 43 | `exchange.hlp_start_of_day_account_value` | `0x54811c2 -> 0x56774c0` | `mov rdx, qword ptr [r15 + 0x10f8]; mov rcx, qword ptr [r15 + 0x1100]` |
| 44 | `exchange.pvs` | `0x54811e1 -> 0x5673f30` | `lea rdx, [r15 + 0x4240]` |
| 45 | `exchange.register_token_gas_auction` | `0x548120c -> 0x5673520` | `lea r8, [r15 + 0x3a00]` |
| 46 | `exchange.perp_deploy_gas_auction` | `0x5481237 -> 0x5673520` | `lea r8, [r15 + 0x3a40]` |
| 47 | `exchange.spot_pair_deploy_gas_auction` | `0x5481262 -> 0x5673520` | `lea r8, [r15 + 0x3a80]` |
| 48 | `exchange.hyper_evm` | `0x5481281 -> 0x5673ff0` | `lea rdx, [r15 + 0x1108]` |
| 49 | `exchange.vtg` | `0x54812a0 -> 0x56784c0` | `lea rdx, [r15 + 0x3d40]` |
| 50 | `exchange.begin_block_logic_guard` | `0x54812cb -> 0x56781f0` | `lea r8, [r15 + 0x4198]` |
| 51 | `exchange.user_to_evm_state` | `0x54812ea -> 0x5676020` | `lea rdx, [r15 + 0x3ff8]` |
| 52 | `exchange.multi_sig_tracker` | `0x5481309 -> 0x5677130` | `lea rdx, [r15 + 0x4018]` |
| 53 | `exchange.reserve_accumulators` | `0x5481328 -> 0x5676f80` | `lea rdx, [r15 + 0x4038]` |
| 54 | `exchange.partial_liquidation_cooldown` | `0x548135c -> 0x5678670` | `mov r8, qword ptr [r15 + 0x37e0]; movq xmm0, qword ptr [r15 + 0x37e8]` |
| 55 | `exchange.evm_enabled` | `0x5481388 -> 0x56783a0` | `movzx r8d, byte ptr [r15 + 0x42ad]` |
| 56 | `exchange.validator_l1_vote_tracker` | `0x54813a7 -> 0x56738f0` | `lea rdx, [r15 + 0x4058]` |
| 57 | `exchange.staking_link_tracker` | `0x54813c6 -> 0x5675030` | `lea rdx, [r15 + 0x40a0]` |
| 58 | `exchange.action_delayer` | `0x54813e5 -> 0x5675fc0` | `lea rdx, [r15 + 0x40c0]` |
| 59 | `exchange.default_hip3_limits` | `0x5481404 -> 0x5679b90` | `lea rdx, [r15 + 0x41a8]` |
| 60 | `exchange.hip3_stale_mark_px_guard` | `0x548142f -> 0x56781f0` | `lea r8, [r15 + 0x41d8]` |
| 61 | `exchange.disabled_precompiles` | `0x548144e -> 0x56773a0` | `lea rdx, [r15 + 0x4250]` |
| 62 | `exchange.lvt` | `0x5481479 -> 0x5676bd0` | `lea r8, [r15 + 0x42a0]` |
| 63 | `exchange.hip3_no_cross` | `0x54814a5 -> 0x56783a0` | `movzx r8d, byte ptr [r15 + 0x42ae]` |
| 64 | `exchange.initial_usdc_evm_system_balance` | `0x54814d0 -> 0x56745d0` | `mov r8, qword ptr [r15 + 0x4268]` |
| 65 | `exchange.validator_l1_stream_tracker` | `0x54814ef -> 0x5675790` | `lea rdx, [r15 + 0x37f0]` |
| 66 | `exchange.user_to_evm_to_l1_wei_remaining` | `0x548151a -> 0x5678ea0` | `lea r8, [r15 + 0x4138]` |
| 67 | `exchange.dex_abstraction_enabled` | `0x5481546 -> 0x56783a0` | `movzx r8d, byte ptr [r15 + 0x42af]` |
| 68 | `exchange.hil` | `0x5481565 -> 0x5677610` | `lea rdx, [r15 + 0x3830]` |
| 69 | `exchange.oh` | `0x5481584 -> 0x5673ad0` | `lea rdx, [r15 + 0x3d78]` |
| 70 | `exchange.pt` | `0x54815a3 -> 0x5676590` | `lea rdx, [r15 + 0x3858]` |
| 71 | `exchange.pmi` | `0x54815c2 -> 0x5677fc0` | `lea rdx, [r15 + 0x42b0]` |
| 72 | `exchange.pmn` | `0x54815ed -> 0x56736b0` | `mov r8, qword ptr [r15 + 0x4270]` |
| 73 | `exchange.lhvt` | `0x548160c -> 0x56787b0` | `lea rdx, [r15 + 0x3d98]` |
| 74 | `exchange.advt` | `0x5481627 -> 0x56778e0` | `lea rdx, [r15 + 0x3e50]` |
| 75 | `exchange.msc` | `0x5481645 -> 0x5675850` | `add r15, 0x3908` |


### Writer-mode and error obligations

- Header choice and exchange/locus key emission inspect writer byte+0xb
  against zero; explicit field-name sites inspect that byte against **one**.
  Fixed-name helper prefixes can use a nonzero test. This report does not
  assume all byte values other than0/1 are valid, or collapse these predicates.
- After **each of the75 value calls**, the owner loads [rsp] to rax, compares
  it with r12 (`0x8000000000000004`) and branches to `0x5481684` on
  inequality. That branch loads the child's two payload words and forwards
  its raw first word plus16-byte payload into the caller result. Later fields
  lie after the success edge; a failed child is not converted to success.
- Header/key failures use the local `0x8000000000000000` result tag and
  preserve the returned payload. Key failures reach `0x5481658`; selected
  header failures first load [rsp+8] before the shared forwarding path.
- Successful completion at `0x5481653` stores only the success tag at [rbx].
  The code does not clear the remaining result words on success.
- These observations concern the owner. A failed writer may have already
  produced output; no rollback/transactionality is established. No destructor,
  deep helper error taxonomy, concrete output bytes or complete wire schema
  is reconstructed by this packet.
- The locus `aux` helper at `0x5673860..0x56738e3` emits its guarded key
  and calls the sequence-header helper with zero. The owner has no source
  field load for this call; do not invent an input offset from a stale register.

## Independent checks and negative controls

static-validation.json records **63 complete FDE contexts /31,450 bytes /
7,640 instructions**: this owner and62 distinct direct callees. GNU/Capstone
instruction address+byte partitions have zero mismatches; GNU readelf
independently agrees with every selected FDE start/end. gnu-contexts.txt and
gnu-frames.txt retain the original selected output. This is an explicit
static context denominator, **not** new-function coverage, helper closure,
compiled-byte equality, a whole-component denominator or Rust equivalence.

The 13 target-grounded tests reproduce retained evidence and exercise:
full-image identity outside the selected code, truncation, changed header
count, moved source displacement, changed/non-ASCII key bytes, changed
success compare and failure destination, a valid but wrong callee, a missing
value dispatch, altered FDE end and ambiguous/unbacked coordinates.
Structural mutation cases deliberately bypass only the full-image identity
function to test extraction sensitivity; the public CLI always checks it.
Mutants exist in memory only and are parsed/disassembled, never executed or
emulated. A changed but structurally valid field/callee must produce a
different report, not silently match the retained evidence. These controls
qualify the static report and do not compare a reconstructed implementation
with target execution.

## Limits and next question

All ABCI/storage/component acceptance gates and byte-window registries remain
unchanged. No Rust source, source ABI identity, state roundtrip, linked node,
deep callee/data/relocation closure, binary equivalence or runtime success is
claimed. Complete direct-callee contexts support auditing key sources but do
not establish all their nested value semantics. Existing contexts already
published in other packets are not counted as new reconstruction.

Next: reconcile this dispatch layout with the corresponding decoder and
complete nested value/error contracts, then derive a whole state-codec
comparison domain before independently implementing that codec.
