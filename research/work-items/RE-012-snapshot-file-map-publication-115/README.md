# RE-012: recover node #115 file mapping result and descriptor lifetime

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The file mapping wrapper uses metadata obtained after opening the input. Metadata tag two bypasses the mmap64 call. In the admitted path the qword at rbp-0x98 supplies the mapping length. The call uses null address, protection one, flags two, the opened descriptor and zero file offset.

The wrapper compares the return pointer with all ones. Only a successful mapping publishes pointer and length at output +8/+16 and sets the leading qword to one. Failure takes the zero-tag arm. The acquired descriptor is closed after both the success and failure publication paths. This evidence concerns the file mapping result and descriptor lifetime, distinct from buffered file reading and metadata conversion.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-file-map-publication-115/collect.py --out work/node115-snapshot-file-map-publication-fresh
python3 -B research/work-items/RE-012-snapshot-file-map-publication-115/verify.py --out work/node115-snapshot-file-map-publication-check-fresh.json
```
