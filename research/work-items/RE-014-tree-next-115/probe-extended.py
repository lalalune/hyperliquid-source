import native,json,mmap
from pathlib import Path
im=native.Image();records=[]
for h in (1,7,8,9,15,16,17):
 m,nodes=native.fixture(im,h,2,2,shape=1);items=[]
 for _ in range(8):
  tag,value=native.step(m);items.append((tag,value))
  if tag!='ITEM':break
 records.append(dict(height=h,items=items))
print('Towercases',json.dumps(records))
controls=[]
specs=[('key-stride',0x37c45f4,0x49,0,2,3,0,0,1),('value-stride',0x37c4600,0x8a,0,2,3,0,0,1),('key-base',0x37c45fc,0x64,0,2,3,0,0,0),('remaining-direction',0x37c443c,0xc0,0,2,3,0,0,0),('next-index',0x37c4595,2,0,2,3,0,0,0),('tag-check',0x37c4443,2,0,2,3,0,0,0),('node-length-field',0x37c445e,0x3c,0,2,3,0,0,0),('right-subtree',0x37c455d,0x40,1,2,2,0,1,2),('parent-index-field',0x37c4542,0x3e,1,2,2,0,1,2)]
for name,va,byte,h,fan,leaf,shape,ready,index in specs:
 mutant=native.Image();mutant.data=mmap.mmap(mutant.view.file.fileno(),0,access=mmap.ACCESS_COPY);mutant.data[mutant.view.offset(va)]=byte
 values=[]
 for image in (im,mutant):
  m,nodes=native.fixture(image,h,fan,leaf,shape=shape,ready=ready,index=index,level=0);result=native.step(m);state=[m.load(native.STATE+8*i,8) for i in range(9)];values.append((result,state))
 if values[0]==values[1]:raise ValueError(('notdistinguishing',name))
 controls.append(dict(name=name,va=hex(va),original_byte=im.view.read(va,1).hex(),mutant_byte=hex(byte),fixture=[h,fan,leaf,shape,ready,index],before=values[0],after=values[1]));mutant.close()
Path(__file__).with_name('native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');print('PASS',len(controls),'realcodecontrols');im.close()
