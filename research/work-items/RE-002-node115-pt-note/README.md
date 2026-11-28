# RE-002: bind node #115 build notes to the loader view

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. No external reference source.

The [section-note study](../RE-002-node115-elf-note-properties/README.md) explicitly excluded program headers. The [load-segment study](../RE-002-node115-load-segment-tls-layout/README.md) reported the PT_NOTE header. This check parses the note records from the program header and reconciles both views, so a candidate link can be checked for program-visible note preservation as well as section contents.

There is one PT_NOTE at file offset and ELF VA 0x2fc, mapped by the first PT_LOAD. Its full range is [0x2fc,0x340). Parsing that range consumes consecutive GNU ABI and build-ID records. Their boundaries exactly match both SHT_NOTE sections, leaving zero bytes between records or after the last record. No GNU property record occurs in this segment. The check makes no inference about arbitrary note-shaped bytes outside PT_NOTE or about linker flags.

From the repository root run:

```sh
python3 research/work-items/RE-002-node115-pt-note/verify.py
```

The attached log records both descriptors and the negative control, which shortens the segment by one byte and fails at the build-ID record. The captured node is only read as bytes. No gate changes.
