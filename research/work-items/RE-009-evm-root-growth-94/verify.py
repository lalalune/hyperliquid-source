#!/usr/bin/env python3
"""Bind one conditional root-growth metadata contract to node94 native bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

HERE = Path(__file__).resolve().parent
NODE = ROOT / "artifacts/node/94/hl-node"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RANGES = ((0x1AB40D6, 0x1AB40E6), (0x1AB45DF, 0x1AB4705))
OWNER_HASH = "93d07eae728e5ddaadc820741e5508fffe77bf2a74f50ec73d3bd448b3124d15"


def span(data, secs, address, size):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid virtual range")
    ss = [s for s in secs if s["type"] != 8 and s["address"] <= address
          and address + size <= s["address"] + s["size"]]
    if len(ss) != 1:
        raise ValueError("range is not uniquely file backed")
    offset = ss[0]["offset"] + address - ss[0]["address"]
    if offset < 0 or offset + size > len(data):
        raise ValueError("range exceeds input")
    return data[offset:offset+size]


def form(data, secs, va, encoded, variable=()):
    expected = bytes.fromhex(encoded)
    raw = span(data, secs, va, len(expected))
    if any(a != b for i,(a,b) in enumerate(zip(raw,expected)) if i not in variable):
        raise ValueError(f"native form changed at {va:#x}")
    return raw


def edge(data, secs, va):
    raw = span(data, secs, va, 6)
    if raw[:2] != b"\xff\x15" and not (raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F):
        raise ValueError("unexpected selected control transfer")
    return {"site":hex(va), "opcode":raw[:2].hex(),
            "target":hex(va+6+struct.unpack_from("<i",raw,2)[0])}


def relocation(data, secs, slot):
    def unique(name):
        rows = [s for s in secs if s["name"] == name and s["type"] != 8]
        if len(rows) != 1:
            raise ValueError("ambiguous/missing relocation metadata section")
        s = rows[0]
        return data[s["offset"]:s["offset"]+s["size"]], s
    rela, sec = unique(".rela.dyn")
    if len(rela) % 24:
        raise ValueError("truncated RELA section")
    rows = [(i,struct.unpack_from("<QQq",rela,i)) for i in range(0,len(rela),24)
            if struct.unpack_from("<Q",rela,i)[0] == slot]
    if len(rows) != 1:
        raise ValueError("selected relocation is not unique")
    at, (_, info, addend) = rows[0]
    result = {"slot":hex(slot), "row_va":hex(sec["address"]+at),
              "raw":rela[at:at+24].hex(), "type":info & 0xFFFFFFFF,
              "symbol_index":info >> 32, "addend":hex(addend)}
    if info >> 32:
        symbols,_ = unique(".dynsym")
        strings,_ = unique(".dynstr")
        si = (info >> 32)*24
        if si+24 > len(symbols):
            raise ValueError("symbol exceeds dynsym")
        name_at = struct.unpack_from("<I",symbols,si)[0]
        end = strings.find(b"\0",name_at)
        if end < name_at:
            raise ValueError("unterminated dynamic symbol")
        result.update(symbol=strings[name_at:end].decode("ascii"), symbol_raw=symbols[si:si+24].hex())
        versions,_ = unique(".gnu.version")
        version_index = struct.unpack_from("<H",versions,(info>>32)*2)[0] & 0x7FFF
        needs,_ = unique(".gnu.version_r")
        found, pos, visited = [], 0, set()
        while pos not in visited:
            visited.add(pos)
            if pos+16 > len(needs):
                raise ValueError("version requirement exceeds section")
            _,count,_,aux,nxt = struct.unpack_from("<HHIII",needs,pos)
            ap = pos+aux
            for _ in range(count):
                if ap+16 > len(needs):
                    raise ValueError("version auxiliary exceeds section")
                _,_,other,name,anext = struct.unpack_from("<IHHII",needs,ap)
                if other & 0x7FFF == version_index:
                    stop = strings.find(b"\0",name)
                    if stop < name:
                        raise ValueError("unterminated symbol version")
                    found.append(strings[name:stop].decode("ascii"))
                ap += anext
            if not nxt:
                break
            pos += nxt
        if len(found) != 1:
            raise ValueError("symbol version is not unique")
        result["version"] = found[0]
    return result


def fields(data, secs=None):
    secs = sections(data) if secs is None else secs
    form(data,secs,0x1AB40D6,"498b87c00200004885c0")
    form(data,secs,0x1AB45DF,"4531ed488b8424c0000000488b184c8b234d85e4")
    form(data,secs,0x1AB45F9,"4c89ed4c8b6b08")
    allocation = struct.unpack_from("<I",form(data,secs,0x1AB4600,"bf30030000",range(1,5)),1)[0]
    form(data,secs,0x1AB460B,"4885c0")
    form(data,secs,0x1AB4614,"4989c748c780c00200000000000066c780ca0200000000")
    old_edge = struct.unpack_from("<I",form(data,secs,0x1AB462B,"4c89a0d0020000",range(3,7)),3)[0]
    form(data,secs,0x1AB4632,"4c89e848ffc0")
    overflow = edge(data,secs,0x1AB4638)
    old_parent = struct.unpack_from("<I",form(data,secs,0x1AB463E,"4d89bc24c0020000",range(4,8)),4)[0]
    form(data,secs,0x1AB4646,"6641c78424c80200000000")
    form(data,secs,0x1AB4651,"4c893b")
    map_height = form(data,secs,0x1AB4654,"48894308",(3,))[3]
    form(data,secs,0x1AB4658,"4c39ed")
    form(data,secs,0x1AB4661,"410fb787ca0200004883f80b")
    form(data,secs,0x1AB4673,"8d4801")
    count = struct.unpack_from("<I",form(data,secs,0x1AB4676,"6641898fca020000",range(4,8)),4)[0]
    form(data,secs,0x1AB467E,"89c2c1e2050f284424500f284c2460410f114c1710410f1104170f284424700f288c2480000000")
    value_lo = struct.unpack_from("<I",form(data,secs,0x1AB46A5,"410f11841760010000",range(5,9)),5)[0]
    value_hi = struct.unpack_from("<I",form(data,secs,0x1AB46AE,"410f118c1770010000",range(5,9)),5)[0]
    new_edge = struct.unpack_from("<I",form(data,secs,0x1AB46B7,"4d89b4c7d8020000",range(4,8)),4)[0]
    form(data,secs,0x1AB46BF,"4d89bec0020000")
    new_index = struct.unpack_from("<I",form(data,secs,0x1AB46C6,"6641898ec8020000",range(4,8)),4)[0]
    form(data,secs,0x1AB46CE,"488b7c24284c8b542410488b8424980000004c8b7c24304c893f488947084c8957104889f84881c4780100005b415c415d415e415f5dc3")
    return {"allocation_size":allocation,"old_edge":old_edge,"old_parent":old_parent,
            "map_height":map_height,"count_store":count,"value_offsets":[value_lo,value_hi],
            "new_edge":new_edge,"new_index":new_index,"overflow":overflow,
            "null_parent":edge(data,secs,0x1AB40E0), "null_root":edge(data,secs,0x1AB45F3),
            "allocation_failure":edge(data,secs,0x1AB460E), "level_guard":edge(data,secs,0x1AB465B),
            "count_guard":edge(data,secs,0x1AB466D), "allocation_call":edge(data,secs,0x1AB4605)}


EXPECTED = {"allocation_size":0x330,"old_edge":0x2D0,"old_parent":0x2C0,
            "map_height":8,"count_store":0x2CA,"value_offsets":[0x160,0x170],
            "new_edge":0x2D8,"new_index":0x2C8}
TARGETS = {"overflow":(0x1AB4638,"0f84",0x1AB49C7),
           "null_parent":(0x1AB40E0,"0f84",0x1AB45DF),
           "null_root":(0x1AB45F3,"0f84",0x1AB49A8),
           "allocation_failure":(0x1AB460E,"0f84",0x1AB49B5),
           "level_guard":(0x1AB465B,"0f85",0x1AB49D6),
           "count_guard":(0x1AB466D,"0f83",0x1AB49EF),
           "allocation_call":(0x1AB4605,"ff15",0x576DFD8)}
EXPECTED.update({name:{"site":hex(a),"opcode":op,"target":hex(t)} for name,(a,op,t) in TARGETS.items()})


def validate(data, secs=None):
    observed = fields(data,secs)
    if observed != EXPECTED:
        raise ValueError("native root-growth contract changed")
    return observed


def increment_height(height):
    if type(height) is not int or not 0 <= height < 2**64:
        raise ValueError("height is not u64")
    result = (height+1) % 2**64
    return result,result == 0


def apply_contract(c, initial, addresses, key, value, selected, local_index):
    """Apply the conditional final-field relation to synthetic disjoint buffers.

    This is a layout model, not execution of target instructions or insertion.
    """
    sizes = {"old":0x2D0,"child":0x2D0,"root":c["allocation_size"],"map":24,"result":24}
    if set(initial) != set(sizes) or set(addresses) != set(sizes):
        raise ValueError("model requires five named objects")
    intervals = []
    for name,size in sizes.items():
        a = addresses[name]
        if type(a) is not int or not 0 < a < 2**64 or a % 8 or a+size > 2**64 or len(initial[name]) != size:
            raise ValueError("model object/address premise failed")
        if any(a < hi and lo < a+size for lo,hi in intervals):
            raise ValueError("fresh/disjoint alias premise failed")
        intervals.append((a,a+size))
    if len(key) != 32 or len(value) != 32 or selected not in (addresses["old"],addresses["child"]):
        raise ValueError("prepared-buffer/selected-child premise failed")
    if type(local_index) is not int or not 0 <= local_index < 2**64:
        raise ValueError("local index is not u64")
    if (struct.unpack_from("<QQ",initial["map"]) != (addresses["old"],0)
            or struct.unpack_from("<Q",initial["old"],0x2C0)[0] != 0):
        raise ValueError("selected zero-height/null-parent entry premise failed")
    if c["overflow"]["opcode"] != "0f84":
        raise ValueError("model is outside selected normal branch")
    out = {name:bytearray(b) for name,b in initial.items()}
    def put(name,offset,fmt,value):
        struct.pack_into(fmt,out[name],offset,value)
    put("root",0x2C0,"<Q",0);put("root",c["count_store"],"<H",1)
    put("root",c["old_edge"],"<Q",addresses["old"])
    put("root",c["new_edge"],"<Q",addresses["child"])
    out["root"][0:32] = key
    for off,part in zip(c["value_offsets"],(value[:16],value[16:])):
        out["root"][off:off+16] = part
    put("old",c["old_parent"],"<Q",addresses["root"]);put("old",0x2C8,"<H",0)
    put("child",0x2C0,"<Q",addresses["root"]);put("child",c["new_index"],"<H",1)
    put("map",0,"<Q",addresses["root"]);put("map",c["map_height"],"<Q",1)
    struct.pack_into("<QQQ",out["result"],0,selected,0,local_index)
    return {name:bytes(b) for name,b in out.items()}


def analyze(data):
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError("node94 identity mismatch")
    secs,index = unwind_index(data)
    cies,fdes = eh_frame_records(data,secs)
    owners = []
    for start,end in ((0x1AB3D20,0x1AB4A43),(0x54C06B0,0x54C0772)):
        matches = [f for f in fdes if f["start"] == start and f["end"] == end]
        if len(matches) != 1:
            raise ValueError("selected owner FDE changed")
        f = matches[0]
        if f["cie"] not in cies or sum(e["start"] == start and e["fde"] == f["fde"] for e in index) != 1:
            raise ValueError("selected FDE/CIE/index membership changed")
        body_hash = hashlib.sha256(span(data,secs,start,end-start)).hexdigest()
        if start == 0x1AB3D20 and body_hash != OWNER_HASH:
            raise ValueError("root-growth owner body changed")
        r = {k:hex(f[k]) if f[k] is not None else None for k in ("start","end","fde","cie","lsda")}
        r.update(body_sha256=body_hash,scope="owner" if start == 0x1AB3D20 else "allocator metadata only; behavior unclosed")
        for k in ("fde","cie"):
            length = int.from_bytes(span(data,secs,f[k],4),"little")+4
            r[k+"_hex"] = span(data,secs,f[k],length).hex()
        owners.append(r)
    allocator = relocation(data,secs,0x576DFD8)
    copy = relocation(data,secs,0x576DFE0)
    if (allocator["type"],allocator["symbol_index"],allocator["addend"]) != (8,0,"0x54c06b0"):
        raise ValueError("allocator relocation changed")
    if (copy["type"],copy["symbol_index"],copy["addend"],copy.get("symbol"),copy.get("version")) != (6,6,"0x0","memcpy","GLIBC_2.14"):
        raise ValueError("credited memcpy import binding changed")
    return {"schema":"re009-evm-root-growth/1","target_sha256":DIGEST,
        "base":"56c0ec672bd8fdcfaa80f2db700a61e6240b3663","owners":owners,
        "fields":validate(data,secs),"allocator_relocation":allocator,
        "credited_memcpy_import":copy,
        "fixed_store_widths_bits":{"parent_pointer":64,"child_edge":64,"map_word":64,
            "node_index":16,"node_count":16,"prepared_half":128,"result_word":64},
        "selected_normal_cfg":[{"site":"0x1ab40e0","taken":True,"next":"0x1ab45df"},
            *[{"site":hex(a),"taken":False,"next":hex(a+6)} for a in
              (0x1AB45F3,0x1AB460E,0x1AB4638,0x1AB465B,0x1AB466D)],
            {"site":"0x1ab4704","next":"return"}],
        "windows":[{"start":hex(a),"end":hex(b),"bytes":span(data,secs,a,b-a).hex()} for a,b in RANGES],
        "counts":{"complete_selected_windows":2,"selected_bytes":sum(b-a for a,b in RANGES),
                  "owner_FDEs_authenticated":1,"allocator_FDEs_metadata_only":1},
        "limits":["Fresh disjoint allocation, valid entry/ABI and stable prepared buffers are premises.",
            "No allocator implementation, fault path, prior memcpy effect or full insertion closure.",
            "No captured execution, source type, runtime ordering, Rust equivalence or acceptance gate."]}


def check_listing(text,data):
    secs = sections(data)
    expected = {a+i:b for a,z in RANGES for i,b in enumerate(span(data,secs,a,z-a))}
    actual = {}
    for line in text.splitlines():
        p = line.split("\t")
        if len(p) < 2 or not p[0].strip().endswith(":"):
            continue
        a = int(p[0].strip()[:-1],16)
        for i,b in enumerate(bytes.fromhex(p[1])):
            if a+i in actual:
                raise ValueError("duplicate exported byte")
            actual[a+i] = b
    if actual != expected:
        raise ValueError("native listing bytes differ or are incomplete")


def main():
    p = argparse.ArgumentParser(description=__doc__);p.add_argument("--out",type=Path);args=p.parse_args()
    data = NODE.read_bytes();record=analyze(data);encoded=json.dumps(record,indent=2,sort_keys=True)+"\n"
    if args.out:
        args.out.mkdir(parents=True,exist_ok=True);(args.out/"evidence.json").write_text(encoded)
    else:
        files = {f.name for f in HERE.iterdir() if f.is_file() and f.name != "MANIFEST.sha256"}
        seen = set()
        for line in (HERE/"MANIFEST.sha256").read_text().splitlines():
            digest,name = line.split("  ")
            if name not in files or name in seen or (HERE/name).is_symlink() or hashlib.sha256((HERE/name).read_bytes()).hexdigest()!=digest:
                raise ValueError("invalid manifest")
            seen.add(name)
        if seen != files or (HERE/"evidence.json").read_text()!=encoded:
            raise ValueError("incomplete manifest or differing evidence")
        check_listing((HERE/"selected.asm").read_text(),data)
    print("node94 root growth: 310 selected native bytes; conditional metadata/child-link contract")


if __name__ == "__main__":
    main()
