# RE-002: Bytes split-off storage representation in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The two complete registered split-off bodies match outside their source relocation fields. The selected in-range split instructions agree with the original length and capacity updates and the returned-view pointer advance.

Place bytes-1.11.1.crate in the local source cache. Run from the repository root with
Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-bytes-split-off-layout/verify.py /path/to/cache
```
