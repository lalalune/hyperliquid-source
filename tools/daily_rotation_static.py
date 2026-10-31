#!/usr/bin/env python3
"""RE-001: shared daily/hourly rotation decisions and three-way flush gate."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-daily-rotation-94'
MIN=1<<63
OWNERS={0x1401d40:(0x1402049,'5b4e64b5df4997d67cca3049a30bafc2536a009cf60657186c8d0bbc1ba7cef2'),
        0x14023c0:(0x1402744,'c47527d5e01aa5c657f722bf3811058da54af8b104dd390a0b11aafc4aa15b51')}
ANCHORS={
    0x1401d51:'31c0',0x1401d53:'483b4748',0x1401d57:'0f8062020000',
    0x1401d63:'3d00100e00',0x1401d68:'0f8363020000',
    0x1401d6e:'3d905f0100',0x1401d73:'0f837d020000',
    0x1401d83:'80bfa800000001',0x1401d8a:'0f8504010000',
    0x1401d92:'41bdc5b3a291',0x1401d98:'4c0fafe8',0x1401d9c:'49c1ed2b',
    0x1401da0:'4538aea9000000',0x1401da7:'750d',0x1401da9:'413bae98000000',
    0x1401db0:'0f84a2010000',0x1401e94:'413bae98000000',0x1401e9b:'0f84b7000000',
    0x1401e79:'4189ae98000000',0x1401e80:'41c686a800000001',0x1401e88:'4588aea9000000',
    0x1401f7e:'418986a4000000',0x1401f88:'4989869c000000',
    0x1401f8f:'4180beaa00000000',0x1401f97:'7426',0x1401fa0:'0fb600',
    0x1401fa3:'84c0',0x1401fa5:'7418',0x1401fa7:'48b80000000000000080',
    0x1401fb1:'483903',0x1401fb4:'7409',
    0x140240b:'31c0',0x140240d:'493b4748',0x1402411:'0f8044020000',
    0x140241a:'3d00100e00',0x140241f:'0f8368020000',
    0x1402425:'3d905f0100',0x140242a:'0f8384020000',
    0x1402436:'4180bfa800000001',0x140243e:'0f85f9000000',
    0x1402446:'41bdc5b3a291',0x140244c:'4c0fafe8',0x1402450:'49c1ed2b',
    0x1402454:'4538afa9000000',0x140245b:'750d',0x140245d:'413baf98000000',
    0x1402464:'0f8484010000',0x140253d:'413baf98000000',0x1402544:'0f84a4000000',
    0x1402522:'4189af98000000',0x1402529:'41c687a800000001',0x1402531:'4588afa9000000',
    0x140261a:'418987a4000000',0x1402624:'4989879c000000',
    0x140262b:'4180bfaa00000000',0x1402633:'7426',0x140263c:'0fb600',
    0x140263f:'84c0',0x1402641:'7418',0x1402643:'48b80000000000000080',
    0x140264d:'493906',0x1402650:'7409',
}
CALLS={0x1401f75:0x13d12a0,0x1402612:0x13d1060,
       0x1401e48:0x1406b80,0x1401f16:0x1406b80,0x14024ec:0x1406b80,0x14025b1:0x1406b80}


def require(ok,message):
    if not ok:raise ValueError(message)


def hour(seconds):
    require(type(seconds) is int and 0<=seconds<90000,'Expected accepted raw second word')
    return seconds*0x91a2b3c5 >> 43


def selected_route(head,seconds,mode,date_equal,old_hour):
    require(type(head) is int and 0<=head<1<<64,'Expected u64 head')
    require(type(seconds) is int and 0<=seconds<1<<32,'Expected u32 seconds')
    require(type(mode) is int and 0<=mode<256 and type(old_hour) is int and 0<=old_hour<256,'Expected raw byte')
    require(type(date_equal) is bool,'Expected date equality')
    if head==MIN:return 'skip'
    if seconds>=921600:return 'time_unwrap_arm'
    if seconds>=90000:return 'hour_assert_arm'
    if mode==1:
        return 'hourly_template' if not date_equal or old_hour!=hour(seconds) else 'no_rotation'
    return 'no_rotation' if date_equal else 'daily_template'


def flush_gate(local,global_byte,post_head):
    require(type(local) is int and 0<=local<256 and type(global_byte) is int and 0<=global_byte<256,'Expected raw byte')
    require(type(post_head) is int and 0<=post_head<1<<64,'Expected u64 post head')
    return bool(local and global_byte and post_head!=MIN)


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Rotation operand/control changed at {va:#x}')
    for va,target in CALLS.items():
        raw=read(va,5)
        require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Rotation/write helper changed')
    for va,slot,target,opcode in [(0x1401f99,0x576ef18,0x5788312,b'\x48\x8b\x05'),
                                 (0x1402635,0x576ef18,0x5788312,b'\x48\x8b\x05'),
                                 (0x1401fb9,0x576eaa8,0x13d1880,b'\xff\x15'),
                                 (0x1402655,0x576eaa8,0x13d1880,b'\xff\x15')]:
        size=len(opcode)+4;raw=read(va,size)
        require(raw.startswith(opcode) and va+size+struct.unpack('<i',raw[-4:])[0]==slot,'Flush pointer/call slot changed')
        require(relocs.get(slot)==target,'Flush relocation changed')
    sources=[]
    for loc,text,line,col in [(0x566aac8,b'/home/ubuntu/hl/code_Mainnet/base/src/time.rs',62,44),
                             (0x5666dd8,b'/home/ubuntu/hl/code_Mainnet/base/src/hour.rs',12,13)]:
        size,actual_line,actual_col=struct.unpack('<QII',read(loc+8,16))
        require(loc in relocs and read(relocs[loc],size)==text and (actual_line,actual_col)==(line,col),'Time/hour source binding changed')
        sources.append({'location':hex(loc),'path':text.decode(),'line':line,'column':col})
    require(read(0x1e9393,15)==b'\xc0\x08/hourly/\xc0\x01/\xc0\0','Hourly template prefix changed')
    _,fdes=eh_frame_records(data);owners=[]
    for start,(end,digest) in OWNERS.items():
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Rotation owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Rotation owner body changed')
        f=fs[0];owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    return {'target_sha256':SHA256,'owners':owners,'source_locations':sources,
            'preconditions':{'skip_head_word':hex(MIN),'time_unwrap_lower_bound':921600,'hour_assert_lower_bound':90000},
            'hour_primitive':{'multiply':0x91a2b3c5,'logical_shift':43,'domain':'0 <= raw second word < 90000'},
            'rotation_fields':{'mode_byte':'0xa8','hour_byte':'0xa9','date_word':'0x98','hourly_mode_word':1},
            'flush_gate':{'local_byte':'0xaa','global_pointer_slot':'0x576ef18','global_byte_va':'0x5788312',
                          'post_head_offset':'0x48','callee':'0x13d1880','condition':'local != 0 && global != 0 && post_head != 0x8000000000000000'},
            'timestamp_store_range':['0x9c','0xa8'],
            'limits':'Raw decisions conditional on valid memory and normal helper returns. Original second-entry API, '
                     'runtime global meaning/value, actual write/flush/open effects, concurrency and Rust ABI unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/daily-rotation-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['flush_gate'])


if __name__=='__main__':main()
