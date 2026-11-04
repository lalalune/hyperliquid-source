"""Independent static byte/relocation checks for one pinned lifecycle callback.
Reads the imported artifact as data; never loads or executes target code.
"""
from pathlib import Path
import hashlib,json,struct
TARGET=Path('artifacts/node/115/hl-node')
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def derive(data):
    shoff=struct.unpack_from('<Q',data,40)[0]
    size,count,index=struct.unpack_from('<HHH',data,58)
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*size) for i in range(count)]
    names=data[headers[index][4]:headers[index][4]+headers[index][5]]
    sections={names[s[0]:].split(b'\0',1)[0].decode():s for s in headers}
    def off(va):
        found=[s[4]+va-s[3] for s in headers if s[1]!=8 and s[2]&2 and s[3]<=va<s[3]+s[5]]
        assert len(found)==1,(hex(va),found)
        return found[0]
    def read(va,n):return data[off(va):off(va)+n]
    def rel32(va):return va+5+struct.unpack('<i',read(va+1,4))[0]
    base=0x14193a0
    # Instruction lengths independently bounded by the retained native decode.
    expected={0:'f30f1efa',4:'803d',11:'75',13:'55',14:'48833d',22:'4889e5',25:'74',27:'488b3d',34:'e8',39:'e8',44:'c605',51:'5d',52:'c3',53:'0f1f00',56:'c3'}
    for delta,prefix in expected.items():assert read(base+delta,len(bytes.fromhex(prefix)))==bytes.fromhex(prefix),(delta,prefix)
    guard_cmp=base+11+struct.unpack('<i',read(base+6,4))[0]
    guard_store=base+51+struct.unpack('<i',read(base+46,4))[0]
    assert guard_cmp==guard_store and read(base+10,1)==b'\0' and read(base+50,1)==b'\1'
    branches=[{'site':hex(base+d),'target':hex(base+d+2+struct.unpack('<b',read(base+d+1,1))[0])} for d in [11,25]]
    calls=[{'site':hex(base+d),'target':hex(rel32(base+d))} for d in [34,39]]
    assert branches==[{'site':'0x14193ab','target':'0x14193d8'},{'site':'0x14193b9','target':'0x14193c7'}]
    assert calls==[{'site':'0x14193c2','target':'0x63f0a40'},{'site':'0x14193c7','target':'0x1419330'}]
    plt=rel32(base+34);rawplt=read(plt,16);got=None
    if rawplt[:2]==b'\xff\x25':got=plt+6+struct.unpack('<i',rawplt[2:6])[0]
    dynsym=sections['.dynsym'];strings=sections['.dynstr'];strdata=data[strings[4]:strings[4]+strings[5]]
    wanted={got,0x64df478,0x64df468};relocs=[]
    for s in headers:
        if s[1]!=4:continue
        for at in range(s[4],s[4]+s[5],s[9]):
            va,info,addend=struct.unpack_from('<QQq',data,at)
            if va not in wanted:continue
            sym=info>>32;nameoff=struct.unpack_from('<I',data,dynsym[4]+sym*dynsym[9])[0]
            name=strdata[nameoff:].split(b'\0',1)[0].decode()
            relocs.append({'va':hex(va),'type':info&0xffffffff,'symbol':name,'addend':addend})
    return {'callback_entry':hex(base),'callback_file_offset':hex(off(base)),'reachable_envelope_end_exclusive':'0x14193d9','guard':hex(guard_cmp),'branches':branches,'direct_calls':calls,'return_sites':['0x14193d4','0x14193d8'],'plt_first16_hex':rawplt.hex(),'plt_got_slot':hex(got) if got is not None else None,'selected_symbol_relocations':relocs,'raw_callback_57_bytes_hex':read(base,57).hex()}
def main():
    data=TARGET.read_bytes();assert hashlib.sha256(data).hexdigest()==SHA
    observed=derive(data)
    controls=[]
    for label,delta in [('entry',0),('conditional_branch',12),('direct_call',35),('guard_store',50)]:
        changed=bytearray(data);changed[int(observed['callback_file_offset'],16)+delta]^=1
        try:derive(changed)
        except AssertionError:controls.append({'mutation':label,'rejected':True})
        else:raise AssertionError('missed mutation '+label)
    assert derive(data)==observed
    result={'target':str(TARGET),'sha256':SHA,'observation':observed,'controls':controls,'identical_input_equal':True,'target_executed':False}
    Path(__file__).with_name('byte-proof.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
