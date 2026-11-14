# Node #115: reverse strictly descending 24-byte runs

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence extending the separately traced large raw-map rebuild's run discovery.

On the selected run-detection path, `0x4f97610..0x4f97695` scans qword keys in 24-byte records. A first pair in descending unsigned order enters a strictly descending scan; the loop stops when a following key is greater than or equal to its predecessor. For a discovered descending run long enough for the selected path, `0x4f976b8..0x4f976cc` selects reversal; nondecreasing runs bypass it.

`0x4f976ce..0x4f97727` swaps three qwords per pair while moving the left pointer forward and right pointer backward by 24 bytes. The loop runs floor(run_length/2) times, reversing complete 24-byte records. Because equality ends a descending scan before reversal, that selected reversal does not invert equal adjacent keys. This does not prove global sort stability, the short-run branch, merging behavior or runtime reachability.

Run `python3 research/work-items/RE-017-node115-raw-map-descending-run-reverse/verify.py` to authenticate the target and validate instruction anchors and mutations without target execution. `windows.txt` records the selected disassembly.
