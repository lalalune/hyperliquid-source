
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000002a64130 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e4300>:
 2a64130:	55                   	push   rbp
 2a64131:	41 57                	push   r15
 2a64133:	41 56                	push   r14
 2a64135:	41 55                	push   r13
 2a64137:	41 54                	push   r12
 2a64139:	53                   	push   rbx
 2a6413a:	48 81 ec f8 00 00 00 	sub    rsp,0xf8
 2a64141:	48 89 94 24 90 00 00 	mov    QWORD PTR [rsp+0x90],rdx
 2a64148:	00 
 2a64149:	48 89 f3             	mov    rbx,rsi
 2a6414c:	0f b6 86 95 01 00 00 	movzx  eax,BYTE PTR [rsi+0x195]
 2a64153:	48 8d 0d fe ee b9 fd 	lea    rcx,[rip+0xfffffffffdb9eefe]        # 603058 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x57453d8>
 2a6415a:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
 2a6415e:	48 01 c8             	add    rax,rcx
 2a64161:	48 89 7c 24 70       	mov    QWORD PTR [rsp+0x70],rdi
 2a64166:	ff e0                	jmp    rax
 2a64168:	0f b6 83 94 01 00 00 	movzx  eax,BYTE PTR [rbx+0x194]
 2a6416f:	c7 83 90 01 00 00 00 	mov    DWORD PTR [rbx+0x190],0x0
 2a64176:	00 00 00 
 2a64179:	48 8d 0d 98 2e ba fd 	lea    rcx,[rip+0xfffffffffdba2e98]        # 607018 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5741418>
 2a64180:	0f b7 04 41          	movzx  eax,WORD PTR [rcx+rax*2]
 2a64184:	c7 43 02 00 00 00 00 	mov    DWORD PTR [rbx+0x2],0x0
 2a6418b:	66 89 43 06          	mov    WORD PTR [rbx+0x6],ax
 2a6418f:	66 c7 03 00 00       	mov    WORD PTR [rbx],0x0
 2a64194:	8b 05 3e c0 a8 03    	mov    eax,DWORD PTR [rip+0x3a8c03e]        # 64f01d8 <__register_atfork@plt+0xfe648>
 2a6419a:	85 c0                	test   eax,eax
 2a6419c:	0f 85 cb 02 00 00    	jne    2a6446d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3fc3>
 2a641a2:	48 8d 4b 20          	lea    rcx,[rbx+0x20]
 2a641a6:	48 89 5b 20          	mov    QWORD PTR [rbx+0x20],rbx
 2a641aa:	48 8d 05 bf 29 9f fd 	lea    rax,[rip+0xfffffffffd9f29bf]        # 456b70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f18c0>
 2a641b1:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
 2a641b5:	48 c7 43 30 10 00 00 	mov    QWORD PTR [rbx+0x30],0x10
 2a641bc:	00 
 2a641bd:	48 c7 43 38 0b 00 00 	mov    QWORD PTR [rbx+0x38],0xb
 2a641c4:	00 
 2a641c5:	48 b8 00 00 00 00 00 	movabs rax,0x4000000000000000
 2a641cc:	00 00 40 
 2a641cf:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
 2a641d3:	48 89 4b 48          	mov    QWORD PTR [rbx+0x48],rcx
 2a641d7:	48 8d 93 88 01 00 00 	lea    rdx,[rbx+0x188]
 2a641de:	c6 83 88 01 00 00 00 	mov    BYTE PTR [rbx+0x188],0x0
 2a641e5:	eb 22                	jmp    2a64209 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e4227>
 2a641e7:	48 8d 93 88 01 00 00 	lea    rdx,[rbx+0x188]
 2a641ee:	0f b6 83 88 01 00 00 	movzx  eax,BYTE PTR [rbx+0x188]
 2a641f5:	48 8d 0d 6c ee b9 fd 	lea    rcx,[rip+0xfffffffffdb9ee6c]        # 603068 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x57453c8>
 2a641fc:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
 2a64200:	48 01 c8             	add    rax,rcx
 2a64203:	ff e0                	jmp    rax
 2a64205:	48 8b 4b 48          	mov    rcx,QWORD PTR [rbx+0x48]
 2a64209:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
 2a6420e:	48 c7 43 60 ff ff ff 	mov    QWORD PTR [rbx+0x60],0xffffffffffffffff
 2a64215:	ff 
 2a64216:	48 89 8b c0 00 00 00 	mov    QWORD PTR [rbx+0xc0],rcx
 2a6421d:	48 8d 83 ca 00 00 00 	lea    rax,[rbx+0xca]
 2a64224:	48 89 44 24 60       	mov    QWORD PTR [rsp+0x60],rax
 2a64229:	c6 83 ca 00 00 00 00 	mov    BYTE PTR [rbx+0xca],0x0
 2a64230:	48 8d 43 50          	lea    rax,[rbx+0x50]
 2a64234:	48 89 44 24 58       	mov    QWORD PTR [rsp+0x58],rax
 2a64239:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
 2a64240:	66 c7 83 c8 00 00 00 	mov    WORD PTR [rbx+0xc8],0x100
 2a64247:	00 01 
 2a64249:	48 89 4b 68          	mov    QWORD PTR [rbx+0x68],rcx
 2a6424d:	48 89 43 70          	mov    QWORD PTR [rbx+0x70],rax
 2a64251:	48 83 f8 01          	cmp    rax,0x1
 2a64255:	48 83 d0 00          	adc    rax,0x0
 2a64259:	48 b9 00 00 00 00 00 	movabs rcx,0x8000000000000000
 2a64260:	00 00 80 
 2a64263:	48 89 4b 78          	mov    QWORD PTR [rbx+0x78],rcx
 2a64267:	48 c7 43 50 00 00 00 	mov    QWORD PTR [rbx+0x50],0x0
 2a6426e:	00 
 2a6426f:	48 89 43 58          	mov    QWORD PTR [rbx+0x58],rax
 2a64273:	31 c9                	xor    ecx,ecx
 2a64275:	48 39 c1             	cmp    rcx,rax
 2a64278:	0f 82 a4 04 00 00    	jb     2a64722 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d0e>
 2a6427e:	c6 83 c9 00 00 00 00 	mov    BYTE PTR [rbx+0xc9],0x0
 2a64285:	48 8b 43 78          	mov    rax,QWORD PTR [rbx+0x78]
 2a64289:	48 b9 00 00 00 00 00 	movabs rcx,0x8000000000000000
 2a64290:	00 00 80 
 2a64293:	48 39 c8             	cmp    rax,rcx
 2a64296:	75 57                	jne    2a642ef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e4141>
 2a64298:	48 c7 44 24 08 01 00 	mov    QWORD PTR [rsp+0x8],0x1
 2a6429f:	00 00 
 2a642a1:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
 2a642a8:	00 00 
 2a642aa:	31 c0                	xor    eax,eax
 2a642ac:	eb 50                	jmp    2a642fe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e4132>
 2a642ae:	4c 8d 83 ca 00 00 00 	lea    r8,[rbx+0xca]
 2a642b5:	0f b6 83 ca 00 00 00 	movzx  eax,BYTE PTR [rbx+0xca]
 2a642bc:	48 8d 73 50          	lea    rsi,[rbx+0x50]
 2a642c0:	48 8d 0d b1 ed b9 fd 	lea    rcx,[rip+0xfffffffffdb9edb1]        # 603078 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x57453b8>
 2a642c7:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
 2a642cb:	48 01 c8             	add    rax,rcx
 2a642ce:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
 2a642d3:	48 89 74 24 58       	mov    QWORD PTR [rsp+0x58],rsi
 2a642d8:	4c 89 44 24 60       	mov    QWORD PTR [rsp+0x60],r8
 2a642dd:	ff e0                	jmp    rax
 2a642df:	48 8b 43 60          	mov    rax,QWORD PTR [rbx+0x60]
 2a642e3:	48 8b 8b c0 00 00 00 	mov    rcx,QWORD PTR [rbx+0xc0]
 2a642ea:	e9 51 ff ff ff       	jmp    2a64240 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e41f0>
 2a642ef:	48 8d 4c 24 08       	lea    rcx,[rsp+0x8]
 2a642f4:	0f 10 83 80 00 00 00 	movups xmm0,XMMWORD PTR [rbx+0x80]
 2a642fb:	0f 11 01             	movups XMMWORD PTR [rcx],xmm0
 2a642fe:	48 89 04 24          	mov    QWORD PTR [rsp],rax
 2a64302:	48 89 e0             	mov    rax,rsp
 2a64305:	48 89 84 24 b0 00 00 	mov    QWORD PTR [rsp+0xb0],rax
 2a6430c:	00 
 2a6430d:	48 8d 05 fc 9f ff ff 	lea    rax,[rip+0xffffffffffff9ffc]        # 2a5e310 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32ea120>
 2a64314:	48 89 84 24 b8 00 00 	mov    QWORD PTR [rsp+0xb8],rax
 2a6431b:	00 
 2a6431c:	48 8d 05 22 0a 9e fd 	lea    rax,[rip+0xfffffffffd9e0a22]        # 444d45 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x59036eb>
 2a64323:	48 89 84 24 a0 00 00 	mov    QWORD PTR [rsp+0xa0],rax
 2a6432a:	00 
 2a6432b:	48 8d 84 24 b0 00 00 	lea    rax,[rsp+0xb0]
 2a64332:	00 
 2a64333:	48 89 84 24 a8 00 00 	mov    QWORD PTR [rsp+0xa8],rax
 2a6433a:	00 
 2a6433b:	48 8d 43 70          	lea    rax,[rbx+0x70]
 2a6433f:	48 89 84 24 98 00 00 	mov    QWORD PTR [rsp+0x98],rax
 2a64346:	00 
 2a64347:	48 8d 84 24 a0 00 00 	lea    rax,[rsp+0xa0]
 2a6434e:	00 
 2a6434f:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 2a64354:	48 8d 05 b5 c2 b9 ff 	lea    rax,[rip+0xffffffffffb9c2b5]        # 2600610 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3747e20>
 2a6435b:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 2a64360:	48 8d 84 24 98 00 00 	lea    rax,[rsp+0x98]
 2a64367:	00 
 2a64368:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
 2a6436d:	48 8d 05 1c bd b9 ff 	lea    rax,[rip+0xffffffffffb9bd1c]        # 2600090 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x37483a0>
 2a64374:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
 2a64379:	48 8d 35 ce 06 9d fd 	lea    rsi,[rip+0xfffffffffd9d06ce]        # 434a4e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x59139e2>
 2a64380:	48 8d 7c 24 78       	lea    rdi,[rsp+0x78]
 2a64385:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
 2a6438a:	ff 15 58 b3 a7 03    	call   QWORD PTR [rip+0x3a7b358]        # 64df6e8 <__register_atfork@plt+0xedb58>
 2a64390:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
 2a64394:	48 85 f6             	test   rsi,rsi
 2a64397:	74 0d                	je     2a643a6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e408a>
 2a64399:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
 2a6439e:	31 d2                	xor    edx,edx
 2a643a0:	ff 15 fa b0 a7 03    	call   QWORD PTR [rip+0x3a7b0fa]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a643a6:	0f 10 44 24 78       	movups xmm0,XMMWORD PTR [rsp+0x78]
 2a643ab:	0f 29 84 24 e0 00 00 	movaps XMMWORD PTR [rsp+0xe0],xmm0
 2a643b2:	00 
 2a643b3:	48 8b 84 24 88 00 00 	mov    rax,QWORD PTR [rsp+0x88]
 2a643ba:	00 
 2a643bb:	48 89 84 24 f0 00 00 	mov    QWORD PTR [rsp+0xf0],rax
 2a643c2:	00 
 2a643c3:	48 8d bc 24 e0 00 00 	lea    rdi,[rsp+0xe0]
 2a643ca:	00 
 2a643cb:	e8 30 dc f9 ff       	call   2a02000 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3346430>
 2a643d0:	49 89 c6             	mov    r14,rax
 2a643d3:	c6 83 c9 00 00 00 00 	mov    BYTE PTR [rbx+0xc9],0x0
 2a643da:	bd 02 00 00 00       	mov    ebp,0x2
 2a643df:	e9 a0 06 00 00       	jmp    2a64a84 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e39ac>
 2a643e4:	4c 8d a3 58 01 00 00 	lea    r12,[rbx+0x158]
 2a643eb:	0f b6 83 58 01 00 00 	movzx  eax,BYTE PTR [rbx+0x158]
 2a643f2:	4c 8d ab d0 00 00 00 	lea    r13,[rbx+0xd0]
 2a643f9:	48 8d 0d 8c ec b9 fd 	lea    rcx,[rip+0xfffffffffdb9ec8c]        # 60308c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x57453a4>
 2a64400:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
 2a64404:	48 01 c8             	add    rax,rcx
 2a64407:	ff e0                	jmp    rax
 2a64409:	e9 54 03 00 00       	jmp    2a64762 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3cce>
 2a6440e:	e9 7e 02 00 00       	jmp    2a64691 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d9f>
 2a64413:	4c 8d bb 50 01 00 00 	lea    r15,[rbx+0x150]
 2a6441a:	0f b6 83 50 01 00 00 	movzx  eax,BYTE PTR [rbx+0x150]
 2a64421:	48 8d 0d 74 ec b9 fd 	lea    rcx,[rip+0xfffffffffdb9ec74]        # 60309c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5745394>
 2a64428:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
 2a6442c:	48 01 c8             	add    rax,rcx
 2a6442f:	ff e0                	jmp    rax
 2a64431:	e9 6a 03 00 00       	jmp    2a647a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3c90>
 2a64436:	0f b7 83 30 01 00 00 	movzx  eax,WORD PTR [rbx+0x130]
 2a6443d:	66 c7 83 30 01 00 00 	mov    WORD PTR [rbx+0x130],0x4
 2a64444:	04 00 
 2a64446:	83 f8 04             	cmp    eax,0x4
 2a64449:	0f 85 86 03 00 00    	jne    2a647d5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3c5b>
 2a6444f:	48 8d 3d 86 28 ba fd 	lea    rdi,[rip+0xfffffffffdba2886]        # 606cdc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5741754>
 2a64456:	48 8d 15 4b 66 9e 03 	lea    rdx,[rip+0x39e664b]        # 644aaa8 <__register_atfork@plt+0x58f18>
 2a6445d:	be 1f 00 00 00       	mov    esi,0x1f
 2a64462:	ff 15 08 b3 a7 03    	call   QWORD PTR [rip+0x3a7b308]        # 64df770 <__register_atfork@plt+0xedbe0>
 2a64468:	e9 12 02 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a6446d:	48 8d 05 4c bd a8 03 	lea    rax,[rip+0x3a8bd4c]        # 64f01c0 <__register_atfork@plt+0xfe630>
 2a64474:	48 89 04 24          	mov    QWORD PTR [rsp],rax
 2a64478:	48 89 e0             	mov    rax,rsp
 2a6447b:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 2a64480:	48 8d 3d 51 bd a8 03 	lea    rdi,[rip+0x3a8bd51]        # 64f01d8 <__register_atfork@plt+0xfe648>
 2a64487:	48 8d 0d c2 9d 99 03 	lea    rcx,[rip+0x3999dc2]        # 63fe250 <__register_atfork@plt+0xc6c0>
 2a6448e:	4c 8d 05 e3 9d 99 03 	lea    r8,[rip+0x3999de3]        # 63fe278 <__register_atfork@plt+0xc6e8>
 2a64495:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
 2a6449a:	be 01 00 00 00       	mov    esi,0x1
 2a6449f:	ff 15 4b b5 a7 03    	call   QWORD PTR [rip+0x3a7b54b]        # 64df9f0 <__register_atfork@plt+0xede60>
 2a644a5:	e9 f8 fc ff ff       	jmp    2a641a2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e428e>
 2a644aa:	48 8d 3d 8f 1d 9e 03 	lea    rdi,[rip+0x39e1d8f]        # 6446240 <__register_atfork@plt+0x546b0>
 2a644b1:	ff 15 a9 ce a7 03    	call   QWORD PTR [rip+0x3a7cea9]        # 64e1360 <__register_atfork@plt+0xef7d0>
 2a644b7:	48 8d 3d 82 1d 9e 03 	lea    rdi,[rip+0x39e1d82]        # 6446240 <__register_atfork@plt+0x546b0>
 2a644be:	ff 15 a4 ce a7 03    	call   QWORD PTR [rip+0x3a7cea4]        # 64e1368 <__register_atfork@plt+0xef7d8>
 2a644c4:	49 89 d7             	mov    r15,rdx
 2a644c7:	48 8d 3d 02 6a 9e 03 	lea    rdi,[rip+0x39e6a02]        # 644aed0 <__register_atfork@plt+0x59340>
 2a644ce:	ff 15 8c ce a7 03    	call   QWORD PTR [rip+0x3a7ce8c]        # 64e1360 <__register_atfork@plt+0xef7d0>
 2a644d4:	e9 a6 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a644d9:	49 89 d7             	mov    r15,rdx
 2a644dc:	48 8d 3d ed 69 9e 03 	lea    rdi,[rip+0x39e69ed]        # 644aed0 <__register_atfork@plt+0x59340>
 2a644e3:	ff 15 7f ce a7 03    	call   QWORD PTR [rip+0x3a7ce7f]        # 64e1368 <__register_atfork@plt+0xef7d8>
 2a644e9:	e9 91 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a644ee:	48 8d 3d 0b 6a 9e 03 	lea    rdi,[rip+0x39e6a0b]        # 644af00 <__register_atfork@plt+0x59370>
 2a644f5:	ff 15 65 ce a7 03    	call   QWORD PTR [rip+0x3a7ce65]        # 64e1360 <__register_atfork@plt+0xef7d0>
 2a644fb:	e9 7f 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64500:	48 8d 3d f9 69 9e 03 	lea    rdi,[rip+0x39e69f9]        # 644af00 <__register_atfork@plt+0x59370>
 2a64507:	ff 15 5b ce a7 03    	call   QWORD PTR [rip+0x3a7ce5b]        # 64e1368 <__register_atfork@plt+0xef7d8>
 2a6450d:	e9 6d 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64512:	48 8d 3d 5f 6a 9e 03 	lea    rdi,[rip+0x39e6a5f]        # 644af78 <__register_atfork@plt+0x593e8>
 2a64519:	ff 15 41 ce a7 03    	call   QWORD PTR [rip+0x3a7ce41]        # 64e1360 <__register_atfork@plt+0xef7d0>
 2a6451f:	e9 5b 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64524:	48 8d 3d 4d 6a 9e 03 	lea    rdi,[rip+0x39e6a4d]        # 644af78 <__register_atfork@plt+0x593e8>
 2a6452b:	ff 15 37 ce a7 03    	call   QWORD PTR [rip+0x3a7ce37]        # 64e1368 <__register_atfork@plt+0xef7d8>
 2a64531:	e9 49 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64536:	48 8d 3d 6b 4e 9e 03 	lea    rdi,[rip+0x39e4e6b]        # 64493a8 <__register_atfork@plt+0x57818>
 2a6453d:	ff 15 1d ce a7 03    	call   QWORD PTR [rip+0x3a7ce1d]        # 64e1360 <__register_atfork@plt+0xef7d0>
 2a64543:	e9 37 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64548:	48 8d 3d 59 4e 9e 03 	lea    rdi,[rip+0x39e4e59]        # 64493a8 <__register_atfork@plt+0x57818>
 2a6454f:	ff 15 13 ce a7 03    	call   QWORD PTR [rip+0x3a7ce13]        # 64e1368 <__register_atfork@plt+0xef7d8>
 2a64555:	e9 25 01 00 00       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a6455a:	49 89 c6             	mov    r14,rax
 2a6455d:	c6 83 95 01 00 00 02 	mov    BYTE PTR [rbx+0x195],0x2
 2a64564:	4c 89 f7             	mov    rdi,r14
 2a64567:	e8 e4 c4 98 03       	call   63f0a50 <_Unwind_Resume@plt>
 2a6456c:	49 89 c6             	mov    r14,rax
 2a6456f:	41 80 3f 03          	cmp    BYTE PTR [r15],0x3
 2a64573:	0f 85 93 00 00 00    	jne    2a6460c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e24>
 2a64579:	66 83 bb 30 01 00 00 	cmp    WORD PTR [rbx+0x130],0x3
 2a64580:	03 
 2a64581:	0f 85 85 00 00 00    	jne    2a6460c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e24>
 2a64587:	48 8d bb 38 01 00 00 	lea    rdi,[rbx+0x138]
 2a6458e:	e8 ed c1 04 00       	call   2ab0780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3297cb0>
 2a64593:	eb 77                	jmp    2a6460c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e24>
 2a64595:	ff 15 25 af a7 03    	call   QWORD PTR [rip+0x3a7af25]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a6459b:	49 89 c6             	mov    r14,rax
 2a6459e:	eb 71                	jmp    2a64611 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e1f>
 2a645a0:	49 89 c6             	mov    r14,rax
 2a645a3:	e9 aa 00 00 00       	jmp    2a64652 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3dde>
 2a645a8:	e9 f7 05 00 00       	jmp    2a64ba4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e388c>
 2a645ad:	49 89 c6             	mov    r14,rax
 2a645b0:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
 2a645b4:	48 85 f6             	test   rsi,rsi
 2a645b7:	74 60                	je     2a64619 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e17>
 2a645b9:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
 2a645be:	31 d2                	xor    edx,edx
 2a645c0:	ff 15 da ae a7 03    	call   QWORD PTR [rip+0x3a7aeda]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a645c6:	80 bb c9 00 00 00 00 	cmp    BYTE PTR [rbx+0xc9],0x0
 2a645cd:	75 53                	jne    2a64622 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e0e>
 2a645cf:	eb 78                	jmp    2a64649 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3de7>
 2a645d1:	49 89 c6             	mov    r14,rax
 2a645d4:	41 80 3f 03          	cmp    BYTE PTR [r15],0x3
 2a645d8:	0f 85 86 00 00 00    	jne    2a64664 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3dcc>
 2a645de:	48 8d 7b 50          	lea    rdi,[rbx+0x50]
 2a645e2:	e8 89 bd 04 00       	call   2ab0370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32980c0>
 2a645e7:	eb 7b                	jmp    2a64664 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3dcc>
 2a645e9:	ff 15 d1 ae a7 03    	call   QWORD PTR [rip+0x3a7aed1]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a645ef:	49 89 c6             	mov    r14,rax
 2a645f2:	66 83 bb 30 01 00 00 	cmp    WORD PTR [rbx+0x130],0x3
 2a645f9:	03 
 2a645fa:	75 0c                	jne    2a64608 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e28>
 2a645fc:	48 8d bb 38 01 00 00 	lea    rdi,[rbx+0x138]
 2a64603:	e8 78 c1 04 00       	call   2ab0780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3297cb0>
 2a64608:	41 c6 07 02          	mov    BYTE PTR [r15],0x2
 2a6460c:	41 c6 04 24 02       	mov    BYTE PTR [r12],0x2
 2a64611:	4c 89 ef             	mov    rdi,r13
 2a64614:	e8 d7 42 06 00       	call   2ac88f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x327fb40>
 2a64619:	80 bb c9 00 00 00 00 	cmp    BYTE PTR [rbx+0xc9],0x0
 2a64620:	74 27                	je     2a64649 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3de7>
 2a64622:	48 8b 73 78          	mov    rsi,QWORD PTR [rbx+0x78]
 2a64626:	48 b8 00 00 00 00 00 	movabs rax,0x8000000000000000
 2a6462d:	00 00 80 
 2a64630:	48 39 c6             	cmp    rsi,rax
 2a64633:	74 14                	je     2a64649 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3de7>
 2a64635:	48 85 f6             	test   rsi,rsi
 2a64638:	74 0f                	je     2a64649 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3de7>
 2a6463a:	48 8b bb 80 00 00 00 	mov    rdi,QWORD PTR [rbx+0x80]
 2a64641:	31 d2                	xor    edx,edx
 2a64643:	ff 15 57 ae a7 03    	call   QWORD PTR [rip+0x3a7ae57]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a64649:	66 c7 83 c9 00 00 00 	mov    WORD PTR [rbx+0xc9],0x200
 2a64650:	00 02 
 2a64652:	48 8b 7c 24 58       	mov    rdi,QWORD PTR [rsp+0x58]
 2a64657:	e8 14 bd 04 00       	call   2ab0370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32980c0>
 2a6465c:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
 2a64661:	c6 00 02             	mov    BYTE PTR [rax],0x2
 2a64664:	c6 83 95 01 00 00 02 	mov    BYTE PTR [rbx+0x195],0x2
 2a6466b:	4c 89 f7             	mov    rdi,r14
 2a6466e:	e8 dd c3 98 03       	call   63f0a50 <_Unwind_Resume@plt>
 2a64673:	ff 15 47 ae a7 03    	call   QWORD PTR [rip+0x3a7ae47]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a64679:	ff 15 41 ae a7 03    	call   QWORD PTR [rip+0x3a7ae41]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a6467f:	0f 0b                	ud2
 2a64681:	49 89 c6             	mov    r14,rax
 2a64684:	4c 89 ef             	mov    rdi,r13
 2a64687:	e8 64 86 05 00       	call   2abccf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x328b740>
 2a6468c:	e9 ba 04 00 00       	jmp    2a64b4b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38e5>
 2a64691:	4c 8d ab f0 00 00 00 	lea    r13,[rbx+0xf0]
 2a64698:	4c 89 ef             	mov    rdi,r13
 2a6469b:	48 8b b4 24 90 00 00 	mov    rsi,QWORD PTR [rsp+0x90]
 2a646a2:	00 
 2a646a3:	e8 a8 c3 02 00       	call   2a90a50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32b79e0>
 2a646a8:	84 c0                	test   al,al
 2a646aa:	0f 85 62 03 00 00    	jne    2a64a12 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3a1e>
 2a646b0:	80 bb 80 01 00 00 03 	cmp    BYTE PTR [rbx+0x180],0x3
 2a646b7:	75 45                	jne    2a646fe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d32>
 2a646b9:	80 bb 78 01 00 00 03 	cmp    BYTE PTR [rbx+0x178],0x3
 2a646c0:	75 3c                	jne    2a646fe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d32>
 2a646c2:	48 8d bb 10 01 00 00 	lea    rdi,[rbx+0x110]
 2a646c9:	80 bb 08 01 00 00 00 	cmp    BYTE PTR [rbx+0x108],0x0
 2a646d0:	74 11                	je     2a646e3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d4d>
 2a646d2:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 2a646d5:	f0 48 ff 08          	lock dec QWORD PTR [rax]
 2a646d9:	75 17                	jne    2a646f2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d3e>
 2a646db:	ff 15 e7 b6 a7 03    	call   QWORD PTR [rip+0x3a7b6e7]        # 64dfdc8 <__register_atfork@plt+0xee238>
 2a646e1:	eb 0f                	jmp    2a646f2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d3e>
 2a646e3:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 2a646e6:	f0 48 ff 08          	lock dec QWORD PTR [rax]
 2a646ea:	75 06                	jne    2a646f2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d3e>
 2a646ec:	ff 15 c6 b6 a7 03    	call   QWORD PTR [rip+0x3a7b6c6]        # 64dfdb8 <__register_atfork@plt+0xee228>
 2a646f2:	48 8d bb 18 01 00 00 	lea    rdi,[rbx+0x118]
 2a646f9:	e8 e2 80 05 00       	call   2abc7e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x328bc50>
 2a646fe:	c6 83 c8 00 00 00 00 	mov    BYTE PTR [rbx+0xc8],0x0
 2a64705:	48 8b bb d0 00 00 00 	mov    rdi,QWORD PTR [rbx+0xd0]
 2a6470c:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 2a6470f:	ff 10                	call   QWORD PTR [rax]
 2a64711:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
 2a64715:	48 8b 43 58          	mov    rax,QWORD PTR [rbx+0x58]
 2a64719:	48 39 c1             	cmp    rcx,rax
 2a6471c:	0f 83 5c fb ff ff    	jae    2a6427e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e41b2>
 2a64722:	48 8d 41 01          	lea    rax,[rcx+0x1]
 2a64726:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
 2a6472a:	48 89 8b 90 00 00 00 	mov    QWORD PTR [rbx+0x90],rcx
 2a64731:	48 8b 43 68          	mov    rax,QWORD PTR [rbx+0x68]
 2a64735:	48 8b 00             	mov    rax,QWORD PTR [rax]
 2a64738:	4c 8d ab d0 00 00 00 	lea    r13,[rbx+0xd0]
 2a6473f:	0f 10 00             	movups xmm0,XMMWORD PTR [rax]
 2a64742:	0f 10 48 10          	movups xmm1,XMMWORD PTR [rax+0x10]
 2a64746:	0f 11 83 d0 00 00 00 	movups XMMWORD PTR [rbx+0xd0],xmm0
 2a6474d:	0f 11 8b e0 00 00 00 	movups XMMWORD PTR [rbx+0xe0],xmm1
 2a64754:	4c 8d a3 58 01 00 00 	lea    r12,[rbx+0x158]
 2a6475b:	c6 83 58 01 00 00 00 	mov    BYTE PTR [rbx+0x158],0x0
 2a64762:	41 0f 10 45 00       	movups xmm0,XMMWORD PTR [r13+0x0]
 2a64767:	41 0f 10 4d 10       	movups xmm1,XMMWORD PTR [r13+0x10]
 2a6476c:	0f 11 8b 00 01 00 00 	movups XMMWORD PTR [rbx+0x100],xmm1
 2a64773:	0f 11 83 f0 00 00 00 	movups XMMWORD PTR [rbx+0xf0],xmm0
 2a6477a:	41 0f 10 45 00       	movups xmm0,XMMWORD PTR [r13+0x0]
 2a6477f:	41 0f 10 4d 10       	movups xmm1,XMMWORD PTR [r13+0x10]
 2a64784:	0f 11 83 10 01 00 00 	movups XMMWORD PTR [rbx+0x110],xmm0
 2a6478b:	0f 11 8b 20 01 00 00 	movups XMMWORD PTR [rbx+0x120],xmm1
 2a64792:	4c 8d bb 50 01 00 00 	lea    r15,[rbx+0x150]
 2a64799:	c6 83 50 01 00 00 00 	mov    BYTE PTR [rbx+0x150],0x0
 2a647a0:	0f 10 83 10 01 00 00 	movups xmm0,XMMWORD PTR [rbx+0x110]
 2a647a7:	0f 10 8b 20 01 00 00 	movups xmm1,XMMWORD PTR [rbx+0x120]
 2a647ae:	0f 11 8b 40 01 00 00 	movups XMMWORD PTR [rbx+0x140],xmm1
 2a647b5:	0f 11 83 30 01 00 00 	movups XMMWORD PTR [rbx+0x130],xmm0
 2a647bc:	0f b7 83 30 01 00 00 	movzx  eax,WORD PTR [rbx+0x130]
 2a647c3:	66 c7 83 30 01 00 00 	mov    WORD PTR [rbx+0x130],0x4
 2a647ca:	04 00 
 2a647cc:	83 f8 04             	cmp    eax,0x4
 2a647cf:	0f 84 7a fc ff ff    	je     2a6444f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3fe1>
 2a647d5:	83 f8 02             	cmp    eax,0x2
 2a647d8:	74 57                	je     2a64831 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3bff>
 2a647da:	48 8b bb 38 01 00 00 	mov    rdi,QWORD PTR [rbx+0x138]
 2a647e1:	83 f8 03             	cmp    eax,0x3
 2a647e4:	74 65                	je     2a6484b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3be5>
 2a647e6:	66 89 44 24 20       	mov    WORD PTR [rsp+0x20],ax
 2a647eb:	8b 83 32 01 00 00    	mov    eax,DWORD PTR [rbx+0x132]
 2a647f1:	89 44 24 22          	mov    DWORD PTR [rsp+0x22],eax
 2a647f5:	0f b7 83 36 01 00 00 	movzx  eax,WORD PTR [rbx+0x136]
 2a647fc:	66 89 44 24 26       	mov    WORD PTR [rsp+0x26],ax
 2a64801:	48 89 7c 24 28       	mov    QWORD PTR [rsp+0x28],rdi
 2a64806:	0f 10 83 40 01 00 00 	movups xmm0,XMMWORD PTR [rbx+0x140]
 2a6480d:	0f 11 44 24 30       	movups XMMWORD PTR [rsp+0x30],xmm0
 2a64812:	48 89 e7             	mov    rdi,rsp
 2a64815:	48 8d 74 24 20       	lea    rsi,[rsp+0x20]
 2a6481a:	ff 15 88 28 a8 03    	call   QWORD PTR [rip+0x3a82888]        # 64e70a8 <__register_atfork@plt+0xf5518>
 2a64820:	83 3c 24 01          	cmp    DWORD PTR [rsp],0x1
 2a64824:	0f 85 5b 01 00 00    	jne    2a64985 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3aab>
 2a6482a:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
 2a6482f:	eb 1a                	jmp    2a6484b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3be5>
 2a64831:	48 8d 35 a8 33 9f fd 	lea    rsi,[rip+0xfffffffffd9f33a8]        # 457be0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f0850>
 2a64838:	ba 20 00 00 00       	mov    edx,0x20
 2a6483d:	bf 14 00 00 00       	mov    edi,0x14
 2a64842:	ff 15 08 bf a7 03    	call   QWORD PTR [rip+0x3a7bf08]        # 64e0750 <__register_atfork@plt+0xeebc0>
 2a64848:	48 89 c7             	mov    rdi,rax
 2a6484b:	41 c6 07 01          	mov    BYTE PTR [r15],0x1
 2a6484f:	bd 02 00 00 00       	mov    ebp,0x2
 2a64854:	e8 77 de f9 ff       	call   2a026d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3345d60>
 2a64859:	c6 83 58 01 00 00 01 	mov    BYTE PTR [rbx+0x158],0x1
 2a64860:	48 89 ab 98 00 00 00 	mov    QWORD PTR [rbx+0x98],rbp
 2a64867:	48 89 83 a0 00 00 00 	mov    QWORD PTR [rbx+0xa0],rax
 2a6486e:	4c 89 b3 a8 00 00 00 	mov    QWORD PTR [rbx+0xa8],r14
 2a64875:	8b 54 24 6c          	mov    edx,DWORD PTR [rsp+0x6c]
 2a64879:	89 93 b0 00 00 00    	mov    DWORD PTR [rbx+0xb0],edx
 2a6487f:	66 89 8b b8 00 00 00 	mov    WORD PTR [rbx+0xb8],cx
 2a64886:	48 83 fd 02          	cmp    rbp,0x2
 2a6488a:	0f 85 a5 01 00 00    	jne    2a64a35 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e39fb>
 2a64890:	48 89 83 d0 00 00 00 	mov    QWORD PTR [rbx+0xd0],rax
 2a64897:	48 8b 43 68          	mov    rax,QWORD PTR [rbx+0x68]
 2a6489b:	48 83 c0 08          	add    rax,0x8
 2a6489f:	48 8d 8b 90 00 00 00 	lea    rcx,[rbx+0x90]
 2a648a6:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 2a648ab:	48 8d 05 9e 33 a4 ff 	lea    rax,[rip+0xffffffffffa4339e]        # 24a7c50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x38a07e0>
 2a648b2:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 2a648b7:	48 89 4c 24 30       	mov    QWORD PTR [rsp+0x30],rcx
 2a648bc:	48 8b 05 05 ae a7 03 	mov    rax,QWORD PTR [rip+0x3a7ae05]        # 64df6c8 <__register_atfork@plt+0xedb38>
 2a648c3:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
 2a648c8:	4c 89 6c 24 40       	mov    QWORD PTR [rsp+0x40],r13
 2a648cd:	48 8b 05 54 b3 a7 03 	mov    rax,QWORD PTR [rip+0x3a7b354]        # 64dfc28 <__register_atfork@plt+0xee098>
 2a648d4:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
 2a648d9:	48 8d 35 ff da 9d fd 	lea    rsi,[rip+0xfffffffffd9ddaff]        # 4423df <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5906051>
 2a648e0:	48 89 e7             	mov    rdi,rsp
 2a648e3:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
 2a648e8:	ff 15 fa ad a7 03    	call   QWORD PTR [rip+0x3a7adfa]        # 64df6e8 <__register_atfork@plt+0xedb58>
 2a648ee:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
 2a648f3:	48 89 83 e8 00 00 00 	mov    QWORD PTR [rbx+0xe8],rax
 2a648fa:	0f 10 04 24          	movups xmm0,XMMWORD PTR [rsp]
 2a648fe:	0f 11 83 d8 00 00 00 	movups XMMWORD PTR [rbx+0xd8],xmm0
 2a64905:	c6 83 c8 00 00 00 00 	mov    BYTE PTR [rbx+0xc8],0x0
 2a6490c:	48 8b 83 e8 00 00 00 	mov    rax,QWORD PTR [rbx+0xe8]
 2a64913:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
 2a64918:	0f 10 83 d8 00 00 00 	movups xmm0,XMMWORD PTR [rbx+0xd8]
 2a6491f:	0f 29 44 24 20       	movaps XMMWORD PTR [rsp+0x20],xmm0
 2a64924:	4c 8d 7b 78          	lea    r15,[rbx+0x78]
 2a64928:	48 8b 73 78          	mov    rsi,QWORD PTR [rbx+0x78]
 2a6492c:	48 b8 00 00 00 00 00 	movabs rax,0x8000000000000000
 2a64933:	00 00 80 
 2a64936:	48 39 c6             	cmp    rsi,rax
 2a64939:	74 14                	je     2a6494f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3ae1>
 2a6493b:	48 85 f6             	test   rsi,rsi
 2a6493e:	74 0f                	je     2a6494f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3ae1>
 2a64940:	48 8b bb 80 00 00 00 	mov    rdi,QWORD PTR [rbx+0x80]
 2a64947:	31 d2                	xor    edx,edx
 2a64949:	ff 15 51 ab a7 03    	call   QWORD PTR [rip+0x3a7ab51]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a6494f:	c6 83 c9 00 00 00 01 	mov    BYTE PTR [rbx+0xc9],0x1
 2a64956:	48 8b 44 24 30       	mov    rax,QWORD PTR [rsp+0x30]
 2a6495b:	49 89 47 10          	mov    QWORD PTR [r15+0x10],rax
 2a6495f:	0f 28 44 24 20       	movaps xmm0,XMMWORD PTR [rsp+0x20]
 2a64964:	41 0f 11 07          	movups XMMWORD PTR [r15],xmm0
 2a64968:	48 8b 43 68          	mov    rax,QWORD PTR [rbx+0x68]
 2a6496c:	f2 0f 10 40 20       	movsd  xmm0,QWORD PTR [rax+0x20]
 2a64971:	f2 0f 11 83 f0 00 00 	movsd  QWORD PTR [rbx+0xf0],xmm0
 2a64978:	00 
 2a64979:	c6 83 80 01 00 00 00 	mov    BYTE PTR [rbx+0x180],0x0
 2a64980:	e9 0c fd ff ff       	jmp    2a64691 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3d9f>
 2a64985:	8b 6c 24 04          	mov    ebp,DWORD PTR [rsp+0x4]
 2a64989:	48 8d 3d e0 0e a6 03 	lea    rdi,[rip+0x3a60ee0]        # 64c5870 <__register_atfork@plt+0xd3ce0>
 2a64990:	ff 15 b2 be a7 03    	call   QWORD PTR [rip+0x3a7beb2]        # 64e0848 <__register_atfork@plt+0xeecb8>
 2a64996:	49 89 d0             	mov    r8,rdx
 2a64999:	89 6c 24 78          	mov    DWORD PTR [rsp+0x78],ebp
 2a6499d:	4c 8d 0d cc 0e a6 03 	lea    r9,[rip+0x3a60ecc]        # 64c5870 <__register_atfork@plt+0xd3ce0>
 2a649a4:	48 89 e7             	mov    rdi,rsp
 2a649a7:	48 8d 74 24 78       	lea    rsi,[rsp+0x78]
 2a649ac:	ba 03 00 00 00       	mov    edx,0x3
 2a649b1:	48 89 c1             	mov    rcx,rax
 2a649b4:	e8 c7 db 28 03       	call   5cf2580 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55eb0>
 2a649b9:	48 8b 2c 24          	mov    rbp,QWORD PTR [rsp]
 2a649bd:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
 2a649c2:	48 83 fd 02          	cmp    rbp,0x2
 2a649c6:	75 15                	jne    2a649dd <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3a53>
 2a649c8:	8b 7c 24 78          	mov    edi,DWORD PTR [rsp+0x78]
 2a649cc:	48 89 c5             	mov    rbp,rax
 2a649cf:	ff 15 a3 b4 a7 03    	call   QWORD PTR [rip+0x3a7b4a3]        # 64dfe78 <__register_atfork@plt+0xee2e8>
 2a649d5:	48 89 ef             	mov    rdi,rbp
 2a649d8:	e9 6e fe ff ff       	jmp    2a6484b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3be5>
 2a649dd:	4c 8b 74 24 10       	mov    r14,QWORD PTR [rsp+0x10]
 2a649e2:	8b 4c 24 78          	mov    ecx,DWORD PTR [rsp+0x78]
 2a649e6:	89 4c 24 6c          	mov    DWORD PTR [rsp+0x6c],ecx
 2a649ea:	c6 83 50 01 00 00 01 	mov    BYTE PTR [rbx+0x150],0x1
 2a649f1:	48 8d 8b f6 00 00 00 	lea    rcx,[rbx+0xf6]
 2a649f8:	80 bb f0 00 00 00 00 	cmp    BYTE PTR [rbx+0xf0],0x0
 2a649ff:	48 8d 93 0c 01 00 00 	lea    rdx,[rbx+0x10c]
 2a64a06:	48 0f 45 ca          	cmovne rcx,rdx
 2a64a0a:	0f b7 09             	movzx  ecx,WORD PTR [rcx]
 2a64a0d:	e9 47 fe ff ff       	jmp    2a64859 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3bd7>
 2a64a12:	48 8b 44 24 60       	mov    rax,QWORD PTR [rsp+0x60]
 2a64a17:	c6 00 04             	mov    BYTE PTR [rax],0x4
 2a64a1a:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
 2a64a1f:	c6 00 03             	mov    BYTE PTR [rax],0x3
 2a64a22:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
 2a64a27:	48 c7 00 02 00 00 00 	mov    QWORD PTR [rax],0x2
 2a64a2e:	b0 03                	mov    al,0x3
 2a64a30:	e9 94 00 00 00       	jmp    2a64ac9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3967>
 2a64a35:	48 8d 8b a8 00 00 00 	lea    rcx,[rbx+0xa8]
 2a64a3c:	48 8b 51 10          	mov    rdx,QWORD PTR [rcx+0x10]
 2a64a40:	48 89 94 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rdx
 2a64a47:	00 
 2a64a48:	0f 10 01             	movups xmm0,XMMWORD PTR [rcx]
 2a64a4b:	0f 29 84 24 c0 00 00 	movaps XMMWORD PTR [rsp+0xc0],xmm0
 2a64a52:	00 
 2a64a53:	48 8b 73 78          	mov    rsi,QWORD PTR [rbx+0x78]
 2a64a57:	48 b9 00 00 00 00 00 	movabs rcx,0x8000000000000000
 2a64a5e:	00 00 80 
 2a64a61:	48 39 ce             	cmp    rsi,rcx
 2a64a64:	49 89 c6             	mov    r14,rax
 2a64a67:	74 14                	je     2a64a7d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e39b3>
 2a64a69:	48 85 f6             	test   rsi,rsi
 2a64a6c:	74 0f                	je     2a64a7d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e39b3>
 2a64a6e:	48 8b bb 80 00 00 00 	mov    rdi,QWORD PTR [rbx+0x80]
 2a64a75:	31 d2                	xor    edx,edx
 2a64a77:	ff 15 23 aa a7 03    	call   QWORD PTR [rip+0x3a7aa23]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a64a7d:	c6 83 c9 00 00 00 00 	mov    BYTE PTR [rbx+0xc9],0x0
 2a64a84:	48 8b 44 24 60       	mov    rax,QWORD PTR [rsp+0x60]
 2a64a89:	c6 00 01             	mov    BYTE PTR [rax],0x1
 2a64a8c:	48 8b 7c 24 58       	mov    rdi,QWORD PTR [rsp+0x58]
 2a64a91:	e8 da b8 04 00       	call   2ab0370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32980c0>
 2a64a96:	83 fd 02             	cmp    ebp,0x2
 2a64a99:	74 46                	je     2a64ae1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e394f>
 2a64a9b:	48 8b 84 24 d0 00 00 	mov    rax,QWORD PTR [rsp+0xd0]
 2a64aa2:	00 
 2a64aa3:	48 8b 4c 24 70       	mov    rcx,QWORD PTR [rsp+0x70]
 2a64aa8:	48 89 41 20          	mov    QWORD PTR [rcx+0x20],rax
 2a64aac:	0f 28 84 24 c0 00 00 	movaps xmm0,XMMWORD PTR [rsp+0xc0]
 2a64ab3:	00 
 2a64ab4:	0f 11 41 10          	movups XMMWORD PTR [rcx+0x10],xmm0
 2a64ab8:	48 89 29             	mov    QWORD PTR [rcx],rbp
 2a64abb:	4c 89 71 08          	mov    QWORD PTR [rcx+0x8],r14
 2a64abf:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
 2a64ac4:	c6 00 01             	mov    BYTE PTR [rax],0x1
 2a64ac7:	b0 01                	mov    al,0x1
 2a64ac9:	88 83 95 01 00 00    	mov    BYTE PTR [rbx+0x195],al
 2a64acf:	48 81 c4 f8 00 00 00 	add    rsp,0xf8
 2a64ad6:	5b                   	pop    rbx
 2a64ad7:	41 5c                	pop    r12
 2a64ad9:	41 5d                	pop    r13
 2a64adb:	41 5e                	pop    r14
 2a64add:	41 5f                	pop    r15
 2a64adf:	5d                   	pop    rbp
 2a64ae0:	c3                   	ret
 2a64ae1:	4c 89 74 24 20       	mov    QWORD PTR [rsp+0x20],r14
 2a64ae6:	48 8d 3d 55 0a ba fd 	lea    rdi,[rip+0xfffffffffdba0a55]        # 605542 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5742eee>
 2a64aed:	48 8d 0d 74 28 9e 03 	lea    rcx,[rip+0x39e2874]        # 6447368 <__register_atfork@plt+0x557d8>
 2a64af4:	4c 8d 05 ed 63 9e 03 	lea    r8,[rip+0x39e63ed]        # 644aee8 <__register_atfork@plt+0x59358>
 2a64afb:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
 2a64b00:	be 2b 00 00 00       	mov    esi,0x2b
 2a64b05:	ff 15 95 ab a7 03    	call   QWORD PTR [rip+0x3a7ab95]        # 64df6a0 <__register_atfork@plt+0xedb10>
 2a64b0b:	e9 6f fb ff ff       	jmp    2a6467f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3db1>
 2a64b10:	49 89 c6             	mov    r14,rax
 2a64b13:	e9 44 fb ff ff       	jmp    2a6465c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3dd4>
 2a64b18:	49 89 c6             	mov    r14,rax
 2a64b1b:	48 8d bb 18 01 00 00 	lea    rdi,[rbx+0x118]
 2a64b22:	e8 b9 7c 05 00       	call   2abc7e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x328bc50>
 2a64b27:	eb 22                	jmp    2a64b4b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38e5>
 2a64b29:	ff 15 91 a9 a7 03    	call   QWORD PTR [rip+0x3a7a991]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a64b2f:	49 89 c6             	mov    r14,rax
 2a64b32:	8b 7c 24 78          	mov    edi,DWORD PTR [rsp+0x78]
 2a64b36:	eb 05                	jmp    2a64b3d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38f3>
 2a64b38:	49 89 c6             	mov    r14,rax
 2a64b3b:	89 ef                	mov    edi,ebp
 2a64b3d:	ff 15 35 b3 a7 03    	call   QWORD PTR [rip+0x3a7b335]        # 64dfe78 <__register_atfork@plt+0xee2e8>
 2a64b43:	e9 c0 fa ff ff       	jmp    2a64608 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e28>
 2a64b48:	49 89 c6             	mov    r14,rax
 2a64b4b:	80 bb c8 00 00 00 00 	cmp    BYTE PTR [rbx+0xc8],0x0
 2a64b52:	74 38                	je     2a64b8c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38a4>
 2a64b54:	48 8b b3 d8 00 00 00 	mov    rsi,QWORD PTR [rbx+0xd8]
 2a64b5b:	48 85 f6             	test   rsi,rsi
 2a64b5e:	74 2c                	je     2a64b8c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38a4>
 2a64b60:	48 8b bb e0 00 00 00 	mov    rdi,QWORD PTR [rbx+0xe0]
 2a64b67:	31 d2                	xor    edx,edx
 2a64b69:	ff 15 31 a9 a7 03    	call   QWORD PTR [rip+0x3a7a931]        # 64df4a0 <__register_atfork@plt+0xed910>
 2a64b6f:	eb 1b                	jmp    2a64b8c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e38a4>
 2a64b71:	49 89 c6             	mov    r14,rax
 2a64b74:	e9 8f fa ff ff       	jmp    2a64608 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e28>
 2a64b79:	49 89 c6             	mov    r14,rax
 2a64b7c:	e9 87 fa ff ff       	jmp    2a64608 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e28>
 2a64b81:	49 89 c6             	mov    r14,rax
 2a64b84:	e9 83 fa ff ff       	jmp    2a6460c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e24>
 2a64b89:	49 89 c6             	mov    r14,rax
 2a64b8c:	c6 83 c8 00 00 00 00 	mov    BYTE PTR [rbx+0xc8],0x0
 2a64b93:	48 8b bb d0 00 00 00 	mov    rdi,QWORD PTR [rbx+0xd0]
 2a64b9a:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 2a64b9d:	ff 10                	call   QWORD PTR [rax]
 2a64b9f:	e9 75 fa ff ff       	jmp    2a64619 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e17>
 2a64ba4:	49 89 c6             	mov    r14,rax
 2a64ba7:	80 bb c9 00 00 00 00 	cmp    BYTE PTR [rbx+0xc9],0x0
 2a64bae:	0f 85 6e fa ff ff    	jne    2a64622 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3e0e>
 2a64bb4:	e9 90 fa ff ff       	jmp    2a64649 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3de7>
 2a64bb9:	49 89 c6             	mov    r14,rax
 2a64bbc:	48 8b 7c 24 20       	mov    rdi,QWORD PTR [rsp+0x20]
 2a64bc1:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 2a64bc4:	ff 10                	call   QWORD PTR [rax]
 2a64bc6:	e9 91 fa ff ff       	jmp    2a6465c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32e3dd4>
 2a64bcb:	ff 15 ef a8 a7 03    	call   QWORD PTR [rip+0x3a7a8ef]        # 64df4c0 <__register_atfork@plt+0xed930>
 2a64bd1:	ff 15 e9 a8 a7 03    	call   QWORD PTR [rip+0x3a7a8e9]        # 64df4c0 <__register_atfork@plt+0xed930>
