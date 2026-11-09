# Node115 decimal gate scaler

Independent `no_std` model of node115 `0x434f790..0x434f901`: for two u64
inputs and a table record, it computes
`Q = (A*C)/(100*10^(b49-b48))`, optionally rounds up on remainder, and admits
only when `Q < floor(u64::MAX/100)`.

Index/scale failures and the saturation of an unrepresentable quotient are
logical host controls, not native panic or ABI claims.

Target identity: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Target-grounded evidence: `research/work-items/RE-006-node115-gate-callee/README.md`.
