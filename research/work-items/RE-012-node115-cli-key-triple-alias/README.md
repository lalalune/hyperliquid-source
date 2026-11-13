# RE-012: executor key-triple alias counterexample

Target Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Component: node runtime / serialization. The existing `RE-005-node115-key-consumers` packet correctly limits its gate-input observation to selected paths, but its broader statement that the shapers read the triple only for deallocation overlooks an alias on a different command branch. This packet supplies a conditional static counterexample and narrows the prior claim.

`RE-012-cli-config-115/CONTRACT.md` places the key triple at config output `+0x78/+0x80/+0x88`. The selected executor copies those words to parent `+0xa8/+0xb0/+0xb8` at `0x2ae44e3..0x2ae44fa`. At `0x2ae45a0` it sets R15 to parent `+0xa8`. The already studied command dispatch (`RE-008-output-flags-origin-115` and [#6776](https://github.com/lalalune/hyperliquid-source/pull/6776)) maps tag 9 to `0x2ae5286`; the existing CLI contract calls tag 9 `print-address`.

On that selected branch, `0x2ae5318` loads `[R15+0x10]`, and `0x2ae5321` loads 16 bytes from `[R15]`; these three qwords are copied to a stack temporary. `0x2ae532a..0x2ae5337` passes the temporary as the second argument to indirect slot `0x64e73d8`, whose RELATIVE relocation resolves to `0x564a410`. This is an additional triple read and call beyond the selected gate-path deallocations. A census of bracketed accesses through the base parent register does not itself detect the equivalent `[R15]` aliases.

The relation assumes the selected config copy, tag-9 dispatch, preserved R15, valid disjoint storage and ordinary control-flow/relocation conditions. It does not inspect any actual key, prove runtime invocation, recover the callee, or contradict the prior conclusion that the selected gate input omits this triple. No credential, network, captured target execution or component-gate change is involved.

Run `python3 research/work-items/RE-012-node115-cli-key-triple-alias/verify.py` to check target identity, instruction anchors, tag-9 table entry, relocation and mutation controls. Static windows are in `windows.txt`.
