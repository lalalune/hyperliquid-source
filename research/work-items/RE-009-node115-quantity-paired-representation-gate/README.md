# RE-009 — Node #115 paired quantity representation gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The caller whose entry is `0x55bef10` checks a returned presence byte at stack offset +0x84. On the present arm it takes the field at +0x168 of the object returned at stack offset +0x88 and supplies the same field pointer to two consecutive calls to `0x3ce8df0` on distinct destination registers. The absent arm bypasses both calls.

The two processing paths in that helper converge on equivalent eligibility checks. One calls `0x454f190`; the other repeats `0x3877d60` until its returned byte is zero. Each then checks that the destination first qword is exactly `0x8000000000000000` and the qword at +0x18 is below 32. On the qualifying branch it extracts the words at +8 and +0x10, clears +8 and +0x18, and subsequently writes a four-word replacement descriptor. This establishes the paired caller and eligibility rule. #7511 covers a different caller and the row-materialization contract.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-paired-representation-gate/verify.py`.
