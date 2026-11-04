from pathlib import Path
import json,mmap
import native
im=native.Image();rows=[]
specs=[('colon-loop',0x168619c,0x3b,b'1;2',8),('colon-final',0x16861e2,0x3b,b'1;2',2),('ipv4-word0-byte-order',0x16860d1,0,b'1.2.3.4',8),('ipv4-word1-byte-order',0x16860d5,0,b'1.2.3.4',8),('first-digit-limit',0x16860fc,5,b'00001',8),('first-radix',0x1686103,10,b'ff',8),('loop-digit-limit',0x16861f8,5,b'1:00001',8),('loop-radix',0x16861ff,10,b'1:f',8),('actual-ipv4-callee-leading-zero',0x167cd64,0x31,b'1:2:01.2.3.4',8)]
for name,va,byte,data,cap in specs:
 mutant=native.Image();mutant.data=mmap.mmap(mutant.view.file.fileno(),0,access=mmap.ACCESS_COPY);mutant.data[mutant.view.offset(va)]=byte
 before,_=native.evaluate(im,data,cap,1);after,_=native.evaluate(mutant,data,cap,1)
 if before==after:raise ValueError(('not distinguishing',name))
 rows.append(dict(name=name,va=hex(va),original_byte=im.view.read(va,1).hex(),mutant_byte=hex(byte),data_hex=data.hex(),cap=cap,canary=1,before=before,after=after));mutant.close()
im.close();Path(__file__).with_name('native-controls.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS',len(rows),'actual semantic controls')
