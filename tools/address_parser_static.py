#!/usr/bin/env python3
"""RE-001: node94 address-parser framing and ASCII acceptance, static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from evm_amount_scale import ROOT, BINARY, SHA256, Image
from fde_extents import eh_frame_records

PACKET = ROOT/'research/work-items/RE-001-address-parser-94'
OWNERS = {
    0x1444a00: (0x1444d6c, '59daa55386cb782b9ee0bc1c9712ed8ed5c5b14a2a5fe42bb81a6048d8ea8c00'),
    0x4eb64f0: (0x4eb68a9, '2149bd77d5168ff0d084c27ed603847edf1b735b70ce0dc6572016f36510215d'),
}
# Exact selected instructions, each validated against the complete exported decode.
ANCHORS = {
    0x1444a14:'4883fa02', 0x1444a18:'0f8205020000',
    0x1444a2a:'81ff30780000', 0x1444a30:'400f94c7', 0x1444a34:'480f45f2',
    0x1444a38:'4883fe28', 0x1444a3c:'0f82e1010000',
    0x1444a45:'488d3c48', 0x1444a4c:'4883c1d8',
    0x1444a52:'803c0fbf', 0x1444a56:'0f8eee020000',
    0x1444a73:'4183f830', 0x1444a77:'0f8530020000',
    0x1444b10:'8038c0', 0x1444b13:'0f8c40020000',
    0x1444b20:'66390da91b2dff', 0x1444b2e:'488d0c7526000000',
    0x1444b36:'488d0450', 0x1444b3e:'4883c226',
    0x1444b86:'488b2df3a93204', 0x1444b96:'ffd5',
    0x1444b9c:'83f803', 0x1444bc0:'83f802', 0x1444bc9:'4288542c20',
    0x1444bd1:'4983fd14', 0x1444bd5:'75b9', 0x1444be1:'ff1599a93204',
    0x1444be7:'837c241003', 0x1444bec:'752e',
    0x1444c14:'c60300', 0x1444d12:'c60301', 0x1444d15:'4889d8',
    0x4eb6539:'458d43bf', 0x4eb653d:'4180f806', 0x4eb6541:'7318',
    0x4eb6547:'4180c3c9', 0x4eb655b:'458d439f', 0x4eb655f:'4180f806',
    0x4eb6563:'7318', 0x4eb6569:'4180c3a9', 0x4eb657d:'458d43d0',
    0x4eb6581:'4180f80a', 0x4eb6585:'0f8383000000',
    0x4eb65e4:'41c0e004', 0x4eb65e8:'4108e8',
    0x4eb65eb:'c70702000000', 0x4eb65f1:'44884704',
    0x4eb661f:'49be0026000001000000', 0x4eb66d8:'49bb0026000001000000',
    0x4eb66b3:'c70703000000', 0x4eb676d:'c6462801',
    0x4eb6771:'c70701000000', 0x4eb6861:'41c70700000000',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def nibble(byte):
    """Captured wrapping-byte range tests; invalid returns None."""
    require(type(byte) is int and 0 <= byte < 256, 'Expected one byte')
    if (byte-0x41) & 255 < 6:
        return (byte+0xc9) & 255
    if (byte-0x61) & 255 < 6:
        return (byte+0xa9) & 255
    value = (byte-0x30) & 255
    return value if value < 10 else None


def ascii_decode(value):
    """Acceptance/output model for ASCII input only; no error-object ABI claim."""
    require(isinstance(value, bytes) and value.isascii(), 'ASCII bytes required')
    if len(value) < 2:
        return None
    body = value[2:] if value[:2] == b'0x' else value
    if len(body) < 40:
        return None
    padding, tail = body[:-40], body[-40:]
    if any(c != 0x30 for c in padding):
        return None
    # The captured inner optional prefix can leave only 38 bytes. Such a tail
    # cannot supply 20 decoded bytes; skipping whitespace also reduces capacity.
    if tail[:2] == b'0x':
        return None
    values = [nibble(c) for c in tail]
    if any(v is None for v in values):
        return None
    return bytes((values[i] << 4) | values[i+1] for i in range(0, 40, 2))


def observe(data):
    img = Image(data); read = img.read; relocs = img.relative_relocs()
    _, fdes = eh_frame_records(data)
    for va, raw in ANCHORS.items():
        require(read(va, len(bytes.fromhex(raw))) == bytes.fromhex(raw), f'Parser operand/control changed at {va:#x}')
    require(read(0x7166d0,2) == b'0x', 'Inner prefix literal changed')
    require(read(0x219834,30) == b'string too short to be Address', 'Short-input diagnostic changed')
    require(read(0x219803,49) == b"trailing characters of Address string must be '0'", 'Padding diagnostic changed')
    require(relocs.get(0x576f580) == 0x4eb64f0, 'Hex iterator relocation changed')
    locations=[]
    for va,line,col in [(0x566a410,100,14),(0x566a428,103,18)]:
        target=relocs.get(va)
        require(target==0x1fd07e, 'Address source relocation changed')
        size,actual_line,actual_col=struct.unpack('<QII',read(va+8,16))
        path=read(target,size).decode('utf8')
        require(path=='/home/ubuntu/hl/code_Mainnet/base/src/address.rs' and (actual_line,actual_col)==(line,col), 'Address source Location changed')
        locations.append({'va':hex(va),'path':path,'line':line,'column':col})
    owners=[]
    for start,(end,digest) in OWNERS.items():
        found=[f for f in fdes if f['start']==start]
        require(len(found)==1 and found[0]['end']==end, 'Parser owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest, 'Parser owner body changed')
        f=found[0]
        owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    mask=struct.unpack('<Q',read(0x4eb661f+2,8))[0]
    require(mask==struct.unpack('<Q',read(0x4eb66d8+2,8))[0], 'Whitespace masks differ')
    return {'target_sha256':SHA256,'owners':owners,'source_locations':locations,
            'input':{'rdi':'output pointer','rsi':'UTF-8 byte pointer','rdx':'byte length'},
            'outer_prefix':'0x only','tail_bytes':read(0x1444a38+3,1)[0],
            'required_decoded_bytes':read(0x1444bd1+3,1)[0],
            'iterator_whitespace_bytes':[b for b in range(33) if mask >> b & 1],
            'iterator_tags':{'byte':2,'end':3,'odd_digits':1,'invalid_character':0},
            'result_observation':{'success_tag':0,'error_tag':1,'success_payload_offsets':[1,21],'rax':'original output pointer'},
            'nibble_domain':{'inputs':256,'accepted':sum(nibble(b) is not None for b in range(256))},
            'limits':'ASCII acceptance/output model only. UTF-8 boundary panic arms are retained, not executed. '
                     'Error construction/display, allocation, full object ABI, caller closure and native equivalence unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256, 'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/address-parser-94.json')
    args=p.parse_args();record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified parser framing and hex iterator:',record['required_decoded_bytes'],'output bytes')


if __name__=='__main__':
    main()
