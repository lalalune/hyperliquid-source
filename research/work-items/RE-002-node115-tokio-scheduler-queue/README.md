# Node #115 scheduler queue insertion

This RE-002 packet examines Tokio local and injection scheduler queue insertion against released Tokio 1.45.1 source. The local queue checks capacity and the injection queue updates its linked tail and length unless closed. Two complete catalogued target bodies are compared with compiled references outside relocation fields. This is separate from earlier MPSC block-list and task-binding packets. Static evidence does not establish the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Run `python3 -B research/work-items/RE-002-node115-tokio-scheduler-queue/verify.py /path/to/vendor-source` from repository root. The log is actual offline output; the manifest covers the packet.
