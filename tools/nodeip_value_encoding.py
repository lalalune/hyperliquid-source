"""RE-001: selected LocalNode value encoding, static synthetic u8 inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records
PACKET=ROOT/'research/work-items/RE-001-nodeip-value-encoding-94'
CASES=[(0x45bc960,0x45bccfb,'9f4450b201347dc6cbbe4b0813e4a177b5c8e3b82ab2ae7b6c7e3e853d494bf4'),
       (0x45bcd00,0x45bcf4c,'2ded8362a92c7d21b381582c35051ec661b75f1ef772e5c16c91250de0eff291'),
       (0x4aec6c0,0x4aeca45,'edda5276503b7329a21de504fee7e103ea051b2a7a507d662c65cab8fde0aa58'),
       (0x4aa4230,0x4aa4616,'d4781f2c55cb632c422f48fc7be1c4e0d637d47f6f438a51cc18f7e3b4f030f4')]
def require(ok,message):
    if not ok:raise ValueError(message)

def local_messagepack(image,value,tag=1):
    """Selected direct stores under sufficient-capacity, normal-helper assumptions.

    Read original immediates and signed-byte branch. Growth/error paths and the
    other variant remain unclosed; no serializer, capture or network executes.
    """
    require(type(value) is int and 0<=value<256,'synthetic u8 required')
    require(tag==image.read(0x45bcd12,3)[2],'outside selected raw variant')
    out=bytearray()
    for va in (0x45bcd2c,0x45bcd47):
        raw=image.read(va,4);require(raw[:3]==bytes.fromhex('c60401'),'unsupported map/key store');out.append(raw[3])
    raw=image.read(0x45bcd69,10);require(raw[:2]==b'\x48\xbf','unsupported key word');out+=raw[2:]
    raw=image.read(0x45bcd77,5);require(raw[:4]==bytes.fromhex('c6440108'),'unsupported key tail');out.append(raw[4])
    raw=image.read(0x4aec6c8,7);require(raw[:3]==bytes.fromhex('4881fa'),'unsupported unsigned limit')
    require(value<struct.unpack_from('<I',raw,3)[0],'outside specialized unsigned-byte path')
    require(image.read(0x4aec6d1,2)==bytes.fromhex('84d2'),'unsigned byte flag test changed')
    branch=image.read(0x4aec6d3,6);require(branch[:2] in (b'\x0f\x88',b'\x0f\x89'),'unsupported signed-byte branch')
    require(0x4aec6d9+struct.unpack_from('<i',branch,2)[0]==0x4aec7b0,'unsigned-byte target changed')
    take=bool(value&128) if branch[1]==0x88 else not bool(value&128)
    if take:
        raw=image.read(0x4aec7c4,5);require(raw[:4]==bytes.fromhex('42c60409'),'unsupported uint8 marker');out.append(raw[4])
        require(image.read(0x4aec7d9,4)==bytes.fromhex('42881409'),'uint8 payload store changed')
    else:require(image.read(0x4aec6ea,4)==bytes.fromhex('42881409'),'fixint payload store changed')
    out.append(value);return bytes(out)

def ip_pre_finalizer(image,octets,flag_1a=0,flag_1c=0):
    """Selected array-route preparation; the finalizer is deliberately opaque."""
    require(len(octets)==4,'four synthetic octets required')
    require(flag_1a==0 and flag_1c!=image.read(0x4aa42af,5)[4],'outside selected array route')
    out=bytearray()
    for va in (0x45bcdb6,0x45bcdd1):out.append(image.read(va,4)[3])
    key=image.read(0x45bcde9,6);require(key[:4]==bytes.fromhex('66c70407'),'unsupported Ip key store');out+=key[4:]
    out.append(image.read(0x4aa4332,4)[3])
    require(image.read(0x4aa42ac,3)==bytes.fromhex('448b36'),'IP word load changed')
    word=int.from_bytes(octets,'little')
    shifts=[0,image.read(0x4aa4384,3)[2],image.read(0x4aa43dc,3)[2],image.read(0x4aa440a,4)[3]]
    for shift in shifts:
        require(0<=shift<=31,'IP shift outside word');value=(word>>shift)&255
        # Reuse the selected native unsigned helper lowering, excluding its
        # LocalNode envelope. This is not a call into a captured function.
        out+=local_messagepack(image,value)[11:]
    return bytes(out)

def decimal_payload(image,value):
    """Specialized arithmetic/lookup lowering for the actual u8 decimal branch.

    No JSON escaping, key helper, buffer allocation or complete JSON object is
    modeled. The original thresholds/scales/table and byte arithmetic are read.
    """
    require(type(value) is int and 0<=value<256,'synthetic u8 required')
    threshold=image.read(0x45bc9fe,2);require(threshold[0]==0x3c,'unsupported hundred threshold')
    small=image.read(0x45bcaf6,4);require(small[:3]==bytes.fromhex('4080fd'),'unsupported ten threshold')
    if value<=threshold[1]:
        if value<small[3]:return bytes([value|image.read(0x45bcafc,4)[3]])
        return image.read(0x6f7dfd+value*2,2)
    first=image.read(0x45bca06,3);second=image.read(0x45bca09,3)
    require(first[:2]==bytes.fromhex('8d0c') and first[2]&63==0,'unsupported first scale')
    require(second[:2]==bytes.fromhex('8d04') and second[2]&63==8,'unsupported second scale')
    factor=1+(1+(1<<(first[2]>>6)))*(1<<(second[2]>>6))
    shift=image.read(0x45bca0c,3);require(shift[:2]==bytes.fromhex('c1e8'),'unsupported decimal shift')
    high=(value*factor)>>shift[2]
    hundred=image.read(0x45bca0f,3);require(hundred[:2]==bytes.fromhex('6bc8'),'unsupported decimal remainder')
    low=(value-high*hundred[2])&255
    require(0<=low<100 and 0<=high<10,'decimal lookup escaped declared range')
    return bytes([high|image.read(0x45bcafc,4)[3]])+image.read(0x6f7dfd+low*2,2)

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'local value FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'local value owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    require(image.read(0x6f7096,9)==b'LocalNode','JSON key label changed')
    require(image.read(0x6f7dfd,200)==b''.join(f'{n:02d}'.encode() for n in range(100)),'decimal digit-pair table changed')
    calls={0x45bcd90:0x4aec6c0,0x45bc9bf:0x49c6940,0x45bcdfa:0x4aa4230,
           0x4aa436d:0x4aec6c0,0x4aa439e:0x4aec6c0,0x4aa43fa:0x4aec6c0,0x4aa4429:0x4aec6c0,0x4aa4507:0x43fa0b0}
    for site,target in calls.items():
        raw=image.read(site,5);require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,'local value helper call changed')
    return dict(target_sha256=SHA256,owners=owners,raw_variant=1,payload_bytes=1,
      messagepack_examples={str(n):local_messagepack(image,n).hex() for n in (0,9,10,99,100,127,128,255)},
      decimal_examples={str(n):decimal_payload(image,n).decode() for n in (0,9,10,99,100,127,128,255)},
      ip_pre_finalizer_examples={octets.hex():ip_pre_finalizer(image,octets).hex() for octets in (bytes(4),bytes([1,2,128,255]),b'\xff'*4)},
      direct_call_edges={hex(k):hex(v) for k,v in calls.items()},
      specification='https://github.com/msgpack/msgpack/blob/master/spec.md',
      limits='Sufficient-capacity normal paths specialized. LocalNode values and Ip array preparation only, with serializer flags +1a=0,+1c!=2. Ip finalizer, other flag modes, JSON key helper/full JSON output, growth/error behavior, caller transport and typed reachability unclosed.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
