# Node #115 raw-map rebuild: adjacent duplicate selection

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is a static, conditional analysis, not an observation of live records.

In the contiguous-record iterator variant selected by the rebuild path, `0x4d581f0` reads a 24-byte record (8-byte key followed by a 12-byte value). A zero first value dword is a terminator. For adjacent equal keys with nonzero first value dwords, `0x4d58290` compares the keys and `0x4d58295..0x4d582a4` replaces the saved value with the newer record's value. A differing next key is retained as lookahead; the current key and saved value are returned. End of input clears lookahead and returns the saved value. If the next record has a zero first value dword, the current value is returned first and the next call terminates.

The tree builder at `0x4cc2a54` calls the iterator, tests the returned first value dword at `0x4cc2a59`, and stops on zero. When its current leaf has fewer than 11 entries, `0x4cc2a10..0x4cc2a4b` inserts the returned key and 12-byte value and increments the total. The larger-leaf path is outside this bounded finding.

Together with the separately documented stable unsigned-key insertion sort for 2–20 input rows, this implies that for a valid rebuild with nonzero values and equal keys, this iterator returns the *last original value* in each equal-key run. This does not establish that duplicate keys occur in production or characterize the large-input sorting path, allocation failures, the full tree builder, or runtime behavior.

Reproduce: `python3 research/work-items/RE-017-node115-raw-map-duplicate-runs/verify.py` checks the whole target digest, instruction anchors, direct calls, and rejects mutated anchors without executing the binary. `windows.txt` contains the objdump excerpts.
