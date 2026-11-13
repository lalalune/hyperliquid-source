# RE-012: node #115 CLI command dispatch target table

Target Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Component: node runtime. `RE-012-cli-config-115/CONTRACT.md` identifies selected-command output tags; `RE-008-output-flags-origin-115` maps executor dispatch cases 2 and 3, `RE-009-abci-state-export-115` maps tag 4, and [#6772](https://github.com/lalalune/hyperliquid-source/pull/6772) conditionally links the extracted output to the executor. This packet records the other table entries and their correspondence to the earlier contract, without attributing the case bodies' full behavior.

At `0x2ae4586..0x2ae45b5`, a qword from parent `+0xc0` is reduced by 2 with a conditional move selecting index 12 on borrow. The actual table base is `0x60411c`; for the observed tags 0..15, the following indices and linked targets result:

| Extracted tag | Contract name | Index | Target |
| --- | --- | --- | --- |
| 0, 1 | change-validator-profile | 12 | `0x2ae481b` |
| 2 | run-non-validator | 0 | `0x2ae45b7` |
| 3 | run-validator | 1 | `0x2ae5421` |
| 4 | translate-abci-state | 2 | `0x2ae4ebc` |
| 5 | send-signed-action | 3 | `0x2ae50d4` |
| 6 | delegate | 4 | `0x2ae4731` |
| 7 | staking-deposit | 5 | `0x2ae54b2` |
| 8 | staking-withdrawal | 6 | `0x2ae5b13` |
| 9 | print-address | 7 | `0x2ae5286` |
| 10 | send-slack-alert | 8 | `0x2ae5cb5` |
| 11 | check-reachability | 9 | `0x2ae4e23` |
| 12 | compute-referrer-states | 10 | `0x2ae5c15` |
| 13 | compute-l4-snapshots | 11 | `0x2ae464d` |
| 14 | not identified by the cited contract | 12 | `0x2ae481b` |
| 15 | approve-non-expiring-agent | 13 | `0x2ae556d` |

Names are conditional on the prior command-extractor contract and the selected normal transfer in #6772; table entries are observed addresses. The target table and arithmetic alone do not prove tag 14 is produced, identify its name, validate those case bodies or establish runtime reachability. Inputs outside 0..15 and error tag 16 are outside this bounded selection. No target code executes and no completion gate changes.

Run `python3 research/work-items/RE-012-node115-cli-command-target-table/verify.py` for target digest, table-dispatch instruction anchor, all 14 table targets, 16 synthetic tag-to-index projections and mutation controls. `windows.txt` preserves the static dispatch and selected target entry disassembly.
