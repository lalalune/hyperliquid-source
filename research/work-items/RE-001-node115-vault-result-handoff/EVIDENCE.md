# RE-001: node #115 vault diagnostic call/result handoff

- Component ID: `vaults`; bounded additional RE-001 static function mapping.
- Target: node #115 Linux x86-64, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Source baseline: `a8a165e65d53abc1c996bcc9b609749529cfc41a`.
- Claim status: static observations and explicit stack-offset inference; no recovered source.
- Included: one existing diagnostic's immediate call and result projection. Excluded: helper consumption/closure, accounting, permissions, callers, execution and gate completion.

## Reproduce

From repository root with the pinned LFS input materialized:

```sh
python3 research/work-items/RE-001-node115-vault-result-handoff/verify.py
python3 -m unittest discover -s tests -p test_node115_vault_result_handoff.py -v
```

Python standard library and GNU objdump only. Exact observed commands, tool versions, hashes, durations and exit codes are retained in RESULTS.json. The verifier reads the target as data and disassembles only the existing 184-byte wrapper range. No captured binary is executed. No downloads or network are needed.

## Evidence

Coordinates are link-time ELF VAs. Reuse `../RE-001-node115-vault-diagnostic/verify.py` for PT_LOAD translation and the source/relocation/Location/CIE/FDE association. Its `selected.objdump.txt` already retains the complete `[0x283c6b0,0x283c768)` range; this packet does not claim new byte discovery or duplicate that excerpt. The source is `l1/src/action/vault_transfer.rs:27:18`; LEA `0x283c6dc` loads Location `0x643bb20` into r11.

The new relation follows the complete instruction sequence from that load to direct call `0x283c6ff -> 0x2c39ab0`, and from the call to the wrapper return. Let P denote rsp after the prologue and before `sub rsp,8` at `0x283c6d8`. The output buffer LEA at `0x283c6e3` supplies P+0x30 in rdi. The three pushes are r11 (Location), r10, rax, followed by the call's return-address push. Consequently the Location is placed at callee-entry rsp+0x18. This proves placement, NOT consumption by the callee and NOT a recovered source-language argument number.

After the call, `add rsp,0x20` restores P. The word comparison at `0x283c70a` reads P+0x30, the same buffer address previously supplied in rdi, and compares it with `0x1a2`. The equal branch `0x283c711 -> 0x283c75a` skips the payload stores and leaves al=0x0e. The non-equal arm copies seven 16-byte chunks from stack P+0x30..0x90 into output rbx+0x10..0x70, then sets al=0x0f. Both reach the byte store `[rbx]=al` at `0x283c75a` and return rbx. These tags are not labelled success/error or assigned accounting meanings.

The existing exchange packet `../RE-001-node115-loc-edge-2c39bfa/README.md` maps a DIFFERENT edge inside the direct callee. It does not prove that this wrapper's stack argument is read. Its helper range is contextual prior research, not independently revalidated helper closure here. The integrated native review already decoded this wrapper; this packet adds the bounded argument/result relation rather than claiming an undiscovered function.

## Implementation and comparison

Independently authored additive Python verifier and real-input tests; reuse existing coordinate proof instead of copying it. The verifier validates the exact uninterrupted prelude, argument setup, call opcode/destination, stack restoration, comparison, branch predicate/destination, payload projection, tag store and epilogue. Native disassembly from the established FDE start checks selected instruction alignment. Corruption controls bypass the digest and assert the appropriate structural failure message. No implementation-equivalence comparison, source reconstruction, Cargo build, normalization masks or full helper analysis is implemented/measured.

## Results and limitations

`replay.json` reports one validated relation over one selected relation, not all vault code or a completion percentage. Local command results are in RESULTS.json; independent validation and repository-wide checks are separate and are not implied by local scoped success. No existing executable source or component/progress catalogue is changed. All gates remain incomplete. Next question: does callee `0x2c39ab0` read the stack-passed Location and which internal outcomes produce the observed word? That is unresolved and outside this packet.
