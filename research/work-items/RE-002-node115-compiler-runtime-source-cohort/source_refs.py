"""Read the data identified by selected Rust ET_REL relocations before linking."""
import hashlib
import struct


def data_definitions(obj, wanted, sections):
    """Yield matching symbol names with their bytes and ELF binding (local or externally visible)."""
    table = sections(obj)
    symtab_index, = [i for i, s in enumerate(table) if s["type"] == 2]
    headers = struct.unpack_from("<Q", obj, 40)[0]
    header_size = struct.unpack_from("<H", obj, 58)[0]
    symtab = table[symtab_index]
    linked = struct.unpack_from("<I", obj, headers + symtab_index * header_size + 40)[0]
    strtab = table[linked]
    if strtab["type"] != 3:
        raise ValueError("ELF symbol table does not link to a string table")
    strings = obj[strtab["offset"]:strtab["offset"] + strtab["size"]]
    for off in range(symtab["offset"], symtab["offset"] + symtab["size"], 24):
        name_offset, info, _, index, value, size = struct.unpack_from("<IBBHQQ", obj, off)
        if not 0 < index < len(table):
            continue  # undefined, absolute, or reserved section index
        section = table[index]
        if (section["type"] != 1 or section["flags"] & 7 != 2
                or not section["name"].startswith(".rodata")):
            continue
        name = strings[name_offset:strings.index(b"\0", name_offset)].decode()
        kind, binding = info & 15, info >> 4
        names = {name} & wanted
        # An assembler can relocate directly against the section. Accept that
        # spelling only when a data symbol independently covers the entire section.
        if kind == 1 and value == 0 and size == section["size"] and section["name"] in wanted:
            names.add(section["name"])
        if not names:
            continue
        if kind == 0 and size == 0 and section["flags"] & 0x10:
            # LLVM emits unnamed-sized local .LCPI labels in SHF_MERGE pools.
            # The ELF section header supplies the real entry size in this case.
            size = struct.unpack_from("<Q", obj, headers + index * header_size + 56)[0]
            if size not in (8, 16) or value % size:
                raise ValueError(f"invalid constant-pool entry for {name}")
        elif kind != 1:
            continue
        if not 0 < size <= section["size"] - value:
            raise ValueError(f"invalid readonly data extent for {name}")
        start = section["offset"] + value
        data = obj[start:start + size]
        for key in names:
            yield key, data, binding


def measure(archives, records, census):
    """Resolve a named local datum first, then a unique exported definition in its source rlib."""
    fields = []
    for record in records:
        for rel, target in zip(record["relocations"], record["relocation_targets"], strict=True):
            expression, minus, bias = target["expression"].rpartition("-0x")
            if not minus or rel["addend"] != -4 or int(bias, 16) != 4 or rel["kind"] not in (2, 9):
                raise ValueError(f"unsupported source data reference: {target}")
            fields.append((record["id"], rel["offset"], record["dependency"], record["member"], expression))
    local, exported = {}, {}
    for dependency, archive in archives.items():
        archive_fields = [(owner, name) for _, _, dep, owner, name in fields if dep == dependency]
        external_names = {name for _, name in archive_fields if not name.startswith(".")}
        for member, obj in census.ar_members(archive.read_bytes()):
            if not member.endswith(".o") or not obj.startswith(b"\x7fELF"):
                continue
            wanted = external_names | {name for owner, name in archive_fields if owner == member}
            for name, data, binding in data_definitions(obj, wanted, census.sections):
                key = (dependency, member, name)
                if key in local:
                    raise ValueError(f"ambiguous local data symbol: {key}")
                local[key] = data
                if binding in (1, 2):
                    exported.setdefault((dependency, name), []).append(data)
    rows = []
    for key, offset, dependency, member, name in fields:
        data = local.get((dependency, member, name))
        if data is None:
            data, = exported.get((dependency, name), [])
        rows.append(dict(id=key, offset=offset, source_size=len(data),
                         source_sha256=hashlib.sha256(data).hexdigest()))
    return rows
