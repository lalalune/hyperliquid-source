#!/usr/bin/env python3
"""Static evidence binding only; never execute or interpret target instructions.

ELF/header/RELA mechanics adapt the independently authored repository MIT
RE-013-visor-duration-value-rust/collect.py, SHA256
4983b30f2864cb444b8b572d3baa63569d00a7d2fc0dab5a3d5c818845f70bc5.
Decoders operate only on an authenticated private read-only snapshot.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
TARGET = "89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def admit_identity(raw):
    require(len(raw)==8305392 and sha(raw)==TARGET,"target identity")


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"))+"\n")


class Image:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little-endian")
        require(struct.unpack_from("<H", data, 18)[0] == 62, "x86-64")
        phoff, shoff = struct.unpack_from("<QQ", data, 32)
        ps, pn, ss, sn, names = struct.unpack_from("<HHHHH", data, 54)
        require(ps == 56 and ss == 64, "header strides")
        require(phoff+ps*pn <= len(data) and shoff+ss*sn <= len(data), "headers truncated")
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, phoff+i*ps) for i in range(pn)]
        hs = [struct.unpack_from("<IIQQQQIIQQ", data, shoff+i*ss) for i in range(sn)]
        require(names < sn, "name-table index")
        table = self.file(hs[names][4], hs[names][5])
        self.sections = {}
        for h in hs:
            require(h[0] < len(table), "section name bounds")
            end = table.find(b"\0", h[0])
            require(end >= 0, "section name terminator")
            name = table[h[0]:end].decode("ascii")
            require(name not in self.sections, "duplicate section name")
            self.sections[name] = h

    def file(self, offset, size):
        require(0 <= offset <= offset+size <= len(self.data), "file bounds")
        return self.data[offset:offset+size]

    def offset(self, address, size):
        hits = [h for h in self.loads if h[0] == 1 and h[3] <= address <= address+size <= h[3]+h[5]]
        require(len(hits) == 1, "ambiguous/unbacked mapping")
        return hits[0][2]+address-hits[0][3]

    def at(self, address, size):
        return self.file(self.offset(address, size), size)

    def record(self, address):
        size = struct.unpack("<I", self.at(address, 4))[0]
        require(0 < size < 0xffffffff, "unsupported frame record")
        return self.at(address, size+4)


def relas(image):
    out = []
    for name,h in image.sections.items():
        if h[1] != 4:
            continue
        require(h[9] == 24 and h[5] % 24 == 0, "RELA stride")
        for off in range(h[4], h[4]+h[5], 24):
            raw = image.file(off, 24)
            dest,info,add = struct.unpack("<QQq",raw)
            out.append(dict(section=name,destination=dest,type=info&0xffffffff,
                            symbol=info>>32,addend=add,file_offset=off,raw=raw.hex()))
    return out


def slot_binding(image, all_relas, slot):
    hits = [r for r in all_relas if r["destination"] < slot+8 and slot < r["destination"]+8]
    require(len(hits) == 1 and hits[0]["destination"] == slot, "unique aligned slot binding")
    row = dict(hits[0])
    require(row["type"] in (6,7,8), "supported relocation writer")
    row["slot_raw"] = image.at(slot,8).hex()
    if row["symbol"]:
        sy = image.sections[".dynsym"]
        require(sy[9] == 24 and row["symbol"]*24+24 <= sy[5], "symbol bounds")
        raw = image.file(sy[4]+row["symbol"]*24,24)
        no = struct.unpack_from("<I",raw)[0]
        table = image.sections[".dynstr"]
        require(no < table[5], "symbol string bounds")
        tail = image.file(table[4]+no,table[5]-no)
        require(b"\0" in tail, "symbol terminator")
        row["symbol_name"] = tail.split(b"\0",1)[0].decode("ascii")
        row["symbol_raw"] = raw.hex()
        if ".gnu.version" in image.sections:
            vs = image.sections[".gnu.version"]
            row["version_raw"] = image.file(vs[4]+2*row["symbol"],2).hex()
    return row


def uleb(image, address, limit):
    value=0
    for shift in range(0,70,7):
        require(address < limit, "ULEB truncated")
        byte=image.at(address,1)[0];address+=1
        value |= (byte&127)<<shift
        if byte<128:
            return value,address
    raise ValueError("ULEB too large")


def frame(image, frames, start, end):
    pattern=(r"^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+ FDE cie=([0-9a-f]+) pc="+
             f"{start:016x}"+r"\.\."+f"{end:016x}"+r"$")
    matches=list(re.finditer(pattern,frames,re.M));require(len(matches)==1,"actual FDE header")
    m=matches[0];sec=image.sections[".eh_frame"];fv=sec[3]+int(m[1],16);cv=sec[3]+int(m[2],16)
    fr=image.record(fv);cr=image.record(cv)
    require(all(sec[3]<=a and a+len(r)<=sec[3]+sec[5] for a,r in [(fv,fr),(cv,cr)]),"frame section bounds")
    require(fr[4:8] != b"\0"*4 and cr[4:8] == b"\0"*4,"FDE/CIE discriminator")
    require(fv+4-struct.unpack_from("<I",fr,4)[0]==cv,"backward CIE pointer")
    require(fv+8+struct.unpack_from("<i",fr,8)[0]==start,"FDE PC-relative start")
    require(struct.unpack_from("<I",fr,12)[0]==end-start,"FDE extent")
    row=dict(fde_va=hex(fv),cie_va=hex(cv),fde_raw=fr.hex(),cie_raw=cr.hex(),native_header=m[0])
    if cr[4:17]==bytes.fromhex("00000000017a5200017810011b"):
        require(fr[16]==0,"zR empty FDE augmentation")
        row["lsda"]=None
    else:
        require(cr[4:19]==bytes.fromhex("00000000017a504c5200017810079b") and cr[23:25]==b"\x1b\x1b" and fr[16]==4,"zPLR encoding")
        personality_slot=cv+19+struct.unpack_from("<i",cr,19)[0]
        lv=fv+17+struct.unpack_from("<i",fr,17)[0]
        ls=image.sections[".gcc_except_table"]
        require(ls[1]==1 and ls[3]<=lv<ls[3]+ls[5],"LSDA section")
        limit=ls[3]+ls[5];pos=lv
        require(image.at(pos,1)==b"\xff","omitted LSDA LPStart");pos+=1
        tt=image.at(pos,1)[0];pos+=1
        typebase=None
        if tt!=255:
            require(tt==0x9b,"admitted LSDA type encoding")
            offset,pos=uleb(image,pos,limit);typebase=pos+offset
            require(typebase<=limit,"LSDA type base")
        require(image.at(pos,1)==b"\x01","ULEB call-site encoding");pos+=1
        size,pos=uleb(image,pos,limit);table_start=pos;table_end=pos+size
        require(table_end<=limit,"LSDA call-site extent")
        sites=[]
        while pos<table_end:
            fields=[]
            for _ in range(4):
                value,pos=uleb(image,pos,table_end);fields.append(value)
            a,n,landing,action=fields
            require(a+n<=end-start and (landing==0 or landing<end-start),"LSDA body-relative range")
            sites.append(dict(start=hex(start+a),bytes=n,landing=None if landing==0 else hex(start+landing),action_offset=action))
        require(pos==table_end,"LSDA exact tiling")
        row["lsda"]=dict(va=hex(lv),header_and_table_raw=image.at(lv,table_end-lv).hex(),
                         table_start=hex(table_start),type_encoding=tt,type_base=None if typebase is None else hex(typebase),
                         call_sites=sites,action_semantics="not claimed")
        row["personality_slot"]=hex(personality_slot)
    return row


def rows(text,image,start,end):
    out=[]
    for line in text.splitlines():
        m=re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$",line)
        if m:out.append((int(m[1],16),bytes.fromhex(m[2]),m[3]))
    pc=start
    for a,b,_ in out:
        require(a==pc and image.at(a,len(b))==b,"decoded address/bytes");pc+=len(b)
    require(pc==end and out,"complete decoded partition")
    return out


def inventory(image, decoded, all_relas):
    calls=[];tails=[];branches=[];rip=[]
    addresses={a for a,_,_ in decoded}
    for a,b,text in decoded:
        mnemonic=text.split()[0]
        if mnemonic.startswith("call") or mnemonic=="jmp" and b[:2]==b"\xff\x25":
            item=dict(site=hex(a),raw=b.hex(),instruction=text)
            if b[0] in (0xe8,0xe9):
                item.update(kind="direct",target=hex(a+5+struct.unpack_from("<i",b,1)[0]))
            elif b[:2] in (b"\xff\x15",b"\xff\x25"):
                slot=a+6+struct.unpack_from("<i",b,2)[0]
                item.update(kind="rip-slot",slot=hex(slot),binding=slot_binding(image,all_relas,slot))
            else:
                item.update(kind="dynamic-register-or-vtable",target="opaque, except manually bound retry R15 load")
            (tails if mnemonic=="jmp" else calls).append(item)
        if mnemonic.startswith("j") and not (mnemonic=="jmp" and b[:2]==b"\xff\x25"):
            if b[0] in (0xeb,*range(0x70,0x80)):
                target=a+2+struct.unpack_from("<b",b,1)[0]
            elif b[0]==0xe9:target=a+5+struct.unpack_from("<i",b,1)[0]
            elif b[:1]==b"\x0f" and 0x80<=b[1]<=0x8f:target=a+6+struct.unpack_from("<i",b,2)[0]
            else:raise ValueError("unadmitted branch encoding")
            branches.append(dict(site=hex(a),raw=b.hex(),target=hex(target),within_export=target in addresses,
                                 conditional=mnemonic!="jmp"))
        if "rip" in text and "#" in text:
            m=re.search(r"#\s*(?:0x)?([0-9a-f]+)",text);require(m is not None,"RIP annotation")
            target=int(m[1],16);rip.append(dict(site=hex(a),raw=b.hex(),target=hex(target)))
    return dict(calls=calls,indirect_tails=tails,branches=branches,rip_references=rip,
                returns=[hex(a) for a,b,_ in decoded if b==b"\xc3"],
                ud2=[hex(a) for a,b,_ in decoded if b==b"\x0f\x0b"],
                limits="Static transfer/data inventory, not instruction evaluation or call/branch feasibility.")


def native(argv,cwd):
    done=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=120)
    require(done.returncode==0 and not done.stderr,"decoder failed")
    return done.stdout.decode()


def unwind_index(image, bodies):
    h=image.sections[".eh_frame_hdr"];base=h[3]
    require(h[1]==1 and image.at(base,4)==bytes.fromhex("011b033b"),"unwind header encoding")
    require(base+4+struct.unpack("<i",image.at(base+4,4))[0]==image.sections[".eh_frame"][3],"unwind frame base")
    count=struct.unpack("<I",image.at(base+8,4))[0]
    require(12+8*count==h[5],"unwind index extent")
    entries=[tuple(base+x for x in struct.unpack("<ii",image.at(base+12+8*i,8))) for i in range(count)]
    require(all(entries[i][0]<entries[i+1][0] for i in range(count-1)),"unwind index ordering")
    selected=[]
    for b in bodies:
        key=(int(b["start"],16),int(b["frame"]["fde_va"],16))
        matches=[i for i,x in enumerate(entries) if x==key]
        require(len(matches)==1,"unwind index body/FDE binding")
        i=matches[0]
        selected.append(dict(name=b["name"],index=i,va=hex(base+12+8*i),raw=image.at(base+12+8*i,8).hex()))
    return dict(va=hex(base),header_raw=image.at(base,12).hex(),count=count,selected=selected)


def collect(binary,out,tools,pins=None):
    raw=binary.read_bytes()
    admit_identity(raw)
    image=Image(raw)
    tool_pins=json.loads((HERE/"TOOL-PINS.json").read_text())
    for name,path in tools.items():
        require(sha(Path(path).resolve().read_bytes())==tool_pins[name]["sha256"],"decoder executable identity")
    # Called only after the module is fully loaded, avoiding import-time work.
    from bind import check
    check(image,pins,json.loads((HERE/"CONTROL-PINS.json").read_text()))
    require(not out.exists(),"fresh output")
    all_relas=relas(image)
    require(len(all_relas)==15595,"all RELA count")
    out.mkdir(parents=True)
    bodies=[]
    with tempfile.TemporaryDirectory(prefix="hl-retry-static-") as temp:
        wd=Path(temp);snapshot=wd/"visor.elf";snapshot.write_bytes(raw);snapshot.chmod(0o400)
        frames=native([tools["readelf"],"--debug-dump=frames","visor.elf"],wd)
        for body in pins["bodies"]:
            a,z=int(body["start"],16),int(body["end"],16)
            text_section=image.sections[".text"]
            require(text_section[1]==1 and text_section[2]&4 and text_section[3]<=a<z<=text_section[3]+text_section[5],"executable text extent")
            require(any(h[0]==1 and h[1]&1 and h[3]<=a<z<=h[3]+h[5] for h in image.loads),"executable segment")
            require(image.offset(a,z-a)==text_section[4]+a-text_section[3],"text/PT_LOAD agreement")
            item=dict(body);item["file_offset"]=image.offset(a,z-a)
            item["frame"]=frame(image,frames,a,z)
            require(item["frame"]==body["frame"],"raw FDE/CIE/LSDA pins")
            partitions={};exports={}
            for label,opts in [("gnu",["-Mintel","--insn-width=16"]),("llvm",["--x86-asm-syntax=intel"])]:
                argv=[tools[label],"-d",*opts,"--start-address="+hex(a),"--stop-address="+hex(z),"visor.elf"]
                text=native(argv,wd);decoded=rows(text,image,a,z)
                partitions[label]=[(pc,b.hex()) for pc,b,_ in decoded]
                filename=body["name"]+"."+label+".txt.gz"
                (out/filename).write_bytes(gzip.compress(text.encode(),mtime=0))
                exports[label]=dict(argv=argv,rows=len(decoded),stdout_sha256=sha(text.encode()),path=filename)
                if label=="gnu":item["inventory"]=inventory(image,decoded,all_relas)
            require(partitions["gnu"]==partitions["llvm"],"independent decoder partition mismatch")
            require(sha(image.at(a,z-a))==body["sha256"] and len(partitions["gnu"])==body["rows"],"body pin")
            item["exports"]=exports;bodies.append(item)
        require(snapshot.read_bytes()==raw,"snapshot changed")
        providers={name:dict(path=path,sha256=sha(Path(path).resolve().read_bytes()),
                    version=native([path,"--version"],wd).strip()) for name,path in tools.items()}
        for name,p in providers.items():
            require(p["sha256"]==tool_pins[name]["sha256"] and p["version"]==tool_pins[name]["version"],"decoder changed/version")
    require(binary.read_bytes()==raw,"input path changed")
    literals=[]
    for p in pins["literals"]:
        data=image.at(int(p["va"],16),p["bytes"])
        require(data.hex()==p["raw"],"literal bytes")
        literals.append(dict(p,file_offset=image.offset(int(p["va"],16),p["bytes"])))
    facts={}
    for p in pins["facts"]:
        actual=int.from_bytes(image.at(int(p["va"],16),p["bytes"]),"little")
        require(actual==p["value"],"operand/data fact "+p["name"]);facts[p["name"]]=actual
    slots={p["slot"]:slot_binding(image,all_relas,int(p["slot"],16)) for p in pins["slots"]}
    for p in pins["slots"]:
        r=slots[p["slot"]];require([r["type"],r["symbol"],r["addend"]]==p["binding"],"slot value")
        require(r.get("symbol_name")==p["name"],"imported symbol name")
    index=unwind_index(image,bodies)
    protected=[(int(b["start"],16),int(b["end"],16)) for b in bodies]
    for b in bodies:
        f=b["frame"]
        for va,raw_key in [("fde_va","fde_raw"),("cie_va","cie_raw")]:
            start=int(f[va],16);protected.append((start,start+len(bytes.fromhex(f[raw_key]))))
        if f["lsda"]:
            start=int(f["lsda"]["va"],16)
            protected.append((start,start+len(bytes.fromhex(f["lsda"]["header_and_table_raw"]))))
    h=image.sections[".eh_frame_hdr"];protected.append((h[3],h[3]+h[5]))
    require(not any(r["destination"]<z and a<r["destination"]+8 for r in all_relas for a,z in protected),"relocation overlaps code/unwind bytes")
    literal_writers=[]
    allowed_slots={int(p["slot"],16) for p in pins["slots"]}
    for p in literals:
        a=int(p["va"],16);z=a+p["bytes"]
        hits=[r for r in all_relas if r["destination"]<z and a<r["destination"]+8]
        require(all(r["destination"] in allowed_slots for r in hits),"unbound literal writer")
        literal_writers.extend(dict(literal=p["name"],slot=hex(r["destination"])) for r in hits)
    result=dict(target=dict(bytes=len(raw),sha256=sha(raw)),bodies=bodies,literals=literals,facts=facts,slots=slots,
                providers=providers,relas=dict(count=len(all_relas),types=dict(Counter(str(r["type"]) for r in all_relas))),
                unwind_index=index,literal_relocation_writers=literal_writers,
                scope="Full core/dependency/context byte exports; ordinary protocol theorem is separate and conditional.")
    write_json(out/"records.json",result)
    print(json.dumps(dict(status="PASS static collection only",bodies=len(bodies),
                         bytes=sum(int(x["end"],16)-int(x["start"],16) for x in bodies),
                         rows=sum(x["rows"] for x in bodies))))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--binary",type=Path,default=REPO/"artifacts/visor/captured/hl-visor")
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--gnu",default="/opt/homebrew/opt/binutils/bin/objdump")
    p.add_argument("--llvm",default="/usr/bin/objdump")
    p.add_argument("--readelf",default="/opt/homebrew/opt/binutils/bin/readelf")
    a=p.parse_args()
    pins=json.loads((HERE/"BASIS-PINS.json").read_text())
    collect(a.binary,a.out,dict(gnu=a.gnu,llvm=a.llvm,readelf=a.readelf),pins)


if __name__=="__main__":
    main()
