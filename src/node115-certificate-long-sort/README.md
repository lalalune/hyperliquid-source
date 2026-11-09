# Node115 certificate normalization

Owned logical normalization for decoded 96-byte QC and 104-byte TC rows. Keys compare lexicographically over all 20 bytes; the last original complete row wins for each key, and retained count selects flat (≤64) or tree (>64) storage class.

The native long-sort stability proof, prior-work credit, original-target verification and scope limits are in [`RE-008-node115-certificate-long-sort`](../../research/work-items/RE-008-node115-certificate-long-sort/README.md).

This crate implements its own merge sort. It does not decode certificates, verify signatures/quorum, emulate native sorting, reproduce native container layouts or claim full consensus completion.
