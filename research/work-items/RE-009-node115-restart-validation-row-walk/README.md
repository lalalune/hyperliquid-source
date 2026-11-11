# RE-009 · Restart validation row walk

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. After the known root comparison and first validation gate, call 0x59eda86 passes the saved input's +0x20 and +0x28 words as pointer and count. The slot relocation binds it to 0x1507680.

Zero count bypasses row traversal. The nonzero path computes the end as pointer plus 72 times count. Mode low byte 3 selects the pointer loaded from slot 0x64dfff8 and its +0x28 member address. Other modes use the pointer from 0x64e0000 and its corresponding member address. The selected row call at 0x15077d4 passes the current row address as its second argument. On the selected normal continuation the cursor advances by 72 and exits the loop at the computed end. The called validator, other loop exits and final aggregation remain boundaries. These observations assume valid spans and nonwrapping arithmetic.

Run `python3 research/work-items/RE-009-node115-restart-validation-row-walk/verify.py` from the repository root for the authenticated byte and relocation checks.

The per-row slot 0x64e0ad8 is bound by a relative relocation to 0x1536a90. A returned first byte of exactly 1 selects a distinct counter path. The counter at stack +0x40 is incremented and replaced with all ones on wrap. The caller then selects its next action using a separate local field. The counter is an observation about tag 1 and does not identify the semantic meaning of that tag.

The helper saves its fourth argument once at entry. Each visit to the selected row call copies the two 16-byte lanes from that saved pointer into the scratch buffer passed as the callee's third argument. The row pointer advances independently. The previously mapped governance packet covers the callee's selector and signature-shaped fields. The new evidence here is the restart caller's separation of the moving row and the shared input address. It does not establish that external writes cannot change the shared bytes between iterations.

The preceding validation gate at 0x59eda66 binds to 0x1506e40. Its selected walk likewise forms a 72-byte end and uses the same row-validation slot. A tag-one result updates a separate saturating count at stack +0x140. These matching traversal features belong to the same comparison. The tables, accumulator storage and other branches differ, so the selected correspondence does not establish equal gate results.
