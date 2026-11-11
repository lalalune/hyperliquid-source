# Node115 compact five-byte projection

Independent `no_std` implementation of the recovered 80-byte-row projection:
copy exactly source offsets `0x45..0x4a` into five-byte output rows, preserving
source order.

The original allocation, dangling-empty representation, result producer,
downstream observer and 176-byte full-result copy remain out of scope.

Target identity: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Target-grounded evidence: `research/work-items/RE-008-node115-execution-projection/README.md`.
