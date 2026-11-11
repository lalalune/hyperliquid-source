# Execution-row ordering dependencies

This crate compares logical iterator results behind two node #115 execution-row ordering paths. The 32-byte row's suffix compares a sequence of 20-byte keys; the 64-byte row compares an unsigned word, a sequence of key/u64 pairs, and then another key sequence. Inputs must already be in the native iterator's visitation order. Physical descriptor decoding, tree/ring traversal and ownership are not implemented. The existing open #4945 selector is credited in `research/work-items/RE-008-node115-execution-order`; its implementation is not duplicated here.
