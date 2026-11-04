
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000002af7150 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x32512e0>:
 2af7150:	55                   	push   rbp
 2af7151:	41 57                	push   r15
 2af7153:	41 56                	push   r14
 2af7155:	41 55                	push   r13
 2af7157:	41 54                	push   r12
 2af7159:	53                   	push   rbx
 2af715a:	48 81 ec 08 02 00 00 	sub    rsp,0x208
 2af7161:	48 89 f5             	mov    rbp,rsi
 2af7164:	48 89 fb             	mov    rbx,rdi
 2af7167:	bf 01 00 00 00       	mov    edi,0x1
 2af716c:	e8 6f d1 18 03       	call   5c842e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4150>
 2af7171:	48 89 44 24 68       	mov    QWORD PTR [rsp+0x68],rax
 2af7176:	89 54 24 2c          	mov    DWORD PTR [rsp+0x2c],edx
 2af717a:	80 bb 60 02 00 00 01 	cmp    BYTE PTR [rbx+0x260],0x1
 2af7181:	48 89 6c 24 08       	mov    QWORD PTR [rsp+0x8],rbp
 2af7186:	75 0a                	jne    2af7192 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x325129e>
 2af7188:	c6 44 24 4b 00       	mov    BYTE PTR [rsp+0x4b],0x0
 2af718d:	e9 6e 02 00 00       	jmp    2af7400 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3251030>
 2af7192:	4c 8d b3 78 02 00 00 	lea    r14,[rbx+0x278]
 2af7199:	8b 83 71 02 00 00    	mov    eax,DWORD PTR [rbx+0x271]
 2af719f:	89 44 24 40          	mov    DWORD PTR [rsp+0x40],eax
 2af71a3:	0f 10 83 61 02 00 00 	movups xmm0,XMMWORD PTR [rbx+0x261]
 2af71aa:	0f 29 44 24 30       	movaps XMMWORD PTR [rsp+0x30],xmm0
 2af71af:	4c 8d a4 24 80 00 00 	lea    r12,[rsp+0x80]
 2af71b6:	00
 2af71b7:	4c 89 e7             	mov    rdi,r12
 2af71ba:	ff 15 d0 97 9e 03    	call   QWORD PTR [rip+0x39e97d0]        # 64e0990 <__register_atfork@plt+0xeee00>
 2af71c0:	4c 89 f7             	mov    rdi,r14
 2af71c3:	4c 89 e6             	mov    rsi,r12
 2af71c6:	ff 15 3c 8e 9e 03    	call   QWORD PTR [rip+0x39e8e3c]        # 64e0008 <__register_atfork@plt+0xee478>
 2af71cc:	41 89 c5             	mov    r13d,eax
 2af71cf:	4c 8b a3 98 02 00 00 	mov    r12,QWORD PTR [rbx+0x298]
 2af71d6:	84 c0                	test   al,al
 2af71d8:	74 4a                	je     2af7224 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x325120c>
 2af71da:	49 8d 74 24 10       	lea    rsi,[r12+0x10]
 2af71df:	48 8d 05 d4 ee b0 fd 	lea    rax,[rip+0xfffffffffdb0eed4]        # 6060ba <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5742376>
 2af71e6:	48 89 84 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rax
 2af71ed:	00
 2af71ee:	48 c7 84 24 90 00 00 	mov    QWORD PTR [rsp+0x90],0x19
 2af71f5:	00 19 00 00 00
 2af71fa:	48 c7 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],0x0
 2af7201:	00 00 00 00 00
 2af7206:	49 8d bc 24 40 01 00 	lea    rdi,[r12+0x140]
 2af720d:	00
 2af720e:	4c 8d 05 33 0f 95 03 	lea    r8,[rip+0x3950f33]        # 6448148 <__register_atfork@plt+0x565b8>
 2af7215:	48 8d 94 24 80 00 00 	lea    rdx,[rsp+0x80]
 2af721c:	00
 2af721d:	31 c9                	xor    ecx,ecx
 2af721f:	e8 6c 28 ec ff       	call   29b9a90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x338e9a0>
 2af7224:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
 2af7228:	44 0f b6 b2 9a 0b 00 	movzx  r14d,BYTE PTR [rdx+0xb9a]
 2af722f:	00
 2af7230:	48 81 c2 88 0d 00 00 	add    rdx,0xd88
 2af7237:	8b 44 24 40          	mov    eax,DWORD PTR [rsp+0x40]
 2af723b:	89 84 24 69 01 00 00 	mov    DWORD PTR [rsp+0x169],eax
 2af7242:	66 0f 28 44 24 30    	movapd xmm0,XMMWORD PTR [rsp+0x30]
 2af7248:	66 0f 11 84 24 59 01 	movupd XMMWORD PTR [rsp+0x159],xmm0
 2af724f:	00 00
 2af7251:	c6 84 24 58 01 00 00 	mov    BYTE PTR [rsp+0x158],0x1
 2af7258:	01
 2af7259:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
 2af7260:	00
 2af7261:	4c 8d bc 24 58 01 00 	lea    r15,[rsp+0x158]
 2af7268:	00
 2af7269:	48 89 ef             	mov    rdi,rbp
 2af726c:	44 89 f6             	mov    esi,r14d
 2af726f:	4c 89 f9             	mov    rcx,r15
 2af7272:	ff 15 78 e9 9e 03    	call   QWORD PTR [rip+0x39ee978]        # 64e5bf0 <__register_atfork@plt+0xf4060>
 2af7278:	49 83 c4 10          	add    r12,0x10
 2af727c:	45 0f b6 c5          	movzx  r8d,r13b
 2af7280:	4c 89 ff             	mov    rdi,r15
 2af7283:	48 89 ee             	mov    rsi,rbp
 2af7286:	44 89 f2             	mov    edx,r14d
 2af7289:	4c 89 e1             	mov    rcx,r12
 2af728c:	ff 15 76 01 9f 03    	call   QWORD PTR [rip+0x39f0176]        # 64e7408 <__register_atfork@plt+0xf5878>
 2af7292:	4c 8b a3 90 02 00 00 	mov    r12,QWORD PTR [rbx+0x290]
 2af7299:	4d 8d 74 24 10       	lea    r14,[r12+0x10]
 2af729e:	48 8d 05 2e ee b0 fd 	lea    rax,[rip+0xfffffffffdb0ee2e]        # 6060d3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x574235d>
 2af72a5:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
 2af72aa:	48 c7 44 24 20 12 00 	mov    QWORD PTR [rsp+0x20],0x12
 2af72b1:	00 00
 2af72b3:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
 2af72ba:	00 00
 2af72bc:	49 81 c4 40 01 00 00 	add    r12,0x140
 2af72c3:	4c 89 b4 24 80 00 00 	mov    QWORD PTR [rsp+0x80],r14
 2af72ca:	00
 2af72cb:	4c 89 bc 24 88 00 00 	mov    QWORD PTR [rsp+0x88],r15
 2af72d2:	00
 2af72d3:	4c 8d 7c 24 10       	lea    r15,[rsp+0x10]
 2af72d8:	4c 89 bc 24 90 00 00 	mov    QWORD PTR [rsp+0x90],r15
 2af72df:	00
 2af72e0:	48 8d 0d 79 0e 95 03 	lea    rcx,[rip+0x3950e79]        # 6448160 <__register_atfork@plt+0x565d0>
 2af72e7:	48 8d b4 24 80 00 00 	lea    rsi,[rsp+0x80]
 2af72ee:	00
 2af72ef:	4c 89 e7             	mov    rdi,r12
 2af72f2:	31 d2                	xor    edx,edx
 2af72f4:	e8 07 73 ec ff       	call   29be600 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3389e30>
 2af72f9:	84 c0                	test   al,al
 2af72fb:	0f 84 d6 00 00 00    	je     2af73d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3251059>
 2af7301:	48 8b 84 24 b8 01 00 	mov    rax,QWORD PTR [rsp+0x1b8]
 2af7308:	00
 2af7309:	48 89 84 24 e0 00 00 	mov    QWORD PTR [rsp+0xe0],rax
 2af7310:	00
 2af7311:	0f 10 84 24 a8 01 00 	movups xmm0,XMMWORD PTR [rsp+0x1a8]
 2af7318:	00
 2af7319:	0f 29 84 24 d0 00 00 	movaps XMMWORD PTR [rsp+0xd0],xmm0
 2af7320:	00
 2af7321:	0f 10 84 24 98 01 00 	movups xmm0,XMMWORD PTR [rsp+0x198]
 2af7328:	00
 2af7329:	0f 29 84 24 c0 00 00 	movaps XMMWORD PTR [rsp+0xc0],xmm0
 2af7330:	00
 2af7331:	0f 10 84 24 58 01 00 	movups xmm0,XMMWORD PTR [rsp+0x158]
 2af7338:	00
 2af7339:	66 0f 10 8c 24 68 01 	movupd xmm1,XMMWORD PTR [rsp+0x168]
 2af7340:	00 00
 2af7342:	66 0f 10 94 24 78 01 	movupd xmm2,XMMWORD PTR [rsp+0x178]
 2af7349:	00 00
 2af734b:	66 0f 10 9c 24 88 01 	movupd xmm3,XMMWORD PTR [rsp+0x188]
 2af7352:	00 00
 2af7354:	66 0f 29 9c 24 b0 00 	movapd XMMWORD PTR [rsp+0xb0],xmm3
 2af735b:	00 00
 2af735d:	66 0f 29 94 24 a0 00 	movapd XMMWORD PTR [rsp+0xa0],xmm2
 2af7364:	00 00
 2af7366:	66 0f 29 8c 24 90 00 	movapd XMMWORD PTR [rsp+0x90],xmm1
 2af736d:	00 00
 2af736f:	0f 29 84 24 80 00 00 	movaps XMMWORD PTR [rsp+0x80],xmm0
 2af7376:	00
 2af7377:	48 8d 05 67 ed b0 fd 	lea    rax,[rip+0xfffffffffdb0ed67]        # 6060e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x574234b>
 2af737e:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
 2af7383:	48 c7 44 24 20 13 00 	mov    QWORD PTR [rsp+0x20],0x13
 2af738a:	00 00
 2af738c:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
 2af7393:	00 00
 2af7395:	4c 89 b4 24 e8 00 00 	mov    QWORD PTR [rsp+0xe8],r14
 2af739c:	00
 2af739d:	4c 89 bc 24 f0 00 00 	mov    QWORD PTR [rsp+0xf0],r15
 2af73a4:	00
 2af73a5:	48 8d 0d cc 0d 95 03 	lea    rcx,[rip+0x3950dcc]        # 6448178 <__register_atfork@plt+0x565e8>
 2af73ac:	48 8d b4 24 80 00 00 	lea    rsi,[rsp+0x80]
 2af73b3:	00
 2af73b4:	4c 89 e7             	mov    rdi,r12
 2af73b7:	31 d2                	xor    edx,edx
 2af73b9:	e8 a2 e4 ec ff       	call   29c5860 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3382bd0>
 2af73be:	0f 28 44 24 30       	movaps xmm0,XMMWORD PTR [rsp+0x30]
 2af73c3:	0f 11 44 24 4c       	movups XMMWORD PTR [rsp+0x4c],xmm0
 2af73c8:	8b 44 24 40          	mov    eax,DWORD PTR [rsp+0x40]
 2af73cc:	89 44 24 5c          	mov    DWORD PTR [rsp+0x5c],eax
 2af73d0:	c6 44 24 4b 01       	mov    BYTE PTR [rsp+0x4b],0x1
 2af73d5:	eb 24                	jmp    2af73fb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3251035>
 2af73d7:	8b 44 24 40          	mov    eax,DWORD PTR [rsp+0x40]
 2af73db:	89 44 24 5c          	mov    DWORD PTR [rsp+0x5c],eax
 2af73df:	0f 28 44 24 30       	movaps xmm0,XMMWORD PTR [rsp+0x30]
 2af73e4:	0f 11 44 24 4c       	movups XMMWORD PTR [rsp+0x4c],xmm0
 2af73e9:	c6 44 24 4b 01       	mov    BYTE PTR [rsp+0x4b],0x1
 2af73ee:	48 8d bc 24 58 01 00 	lea    rdi,[rsp+0x158]
 2af73f5:	00
 2af73f6:	e8 15 10 fc ff       	call   2ab8410 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3290020>
 2af73fb:	48 8b 6c 24 08       	mov    rbp,QWORD PTR [rsp+0x8]
 2af7400:	66 0f 10 83 d0 02 00 	movupd xmm0,XMMWORD PTR [rbx+0x2d0]
 2af7407:	00
 2af7408:	66 0f 11 84 24 88 00 	movupd XMMWORD PTR [rsp+0x88],xmm0
 2af740f:	00 00
 2af7411:	48 c7 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],0x1
 2af7418:	00 01 00 00 00
 2af741d:	48 8d bc 24 58 01 00 	lea    rdi,[rsp+0x158]
 2af7424:	00
 2af7425:	48 8d 94 24 80 00 00 	lea    rdx,[rsp+0x80]
 2af742c:	00
 2af742d:	48 8d 4c 24 4b       	lea    rcx,[rsp+0x4b]
 2af7432:	48 89 ee             	mov    rsi,rbp
 2af7435:	e8 46 f1 ff ff       	call   2af6580 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3251eb0>
 2af743a:	48 8b 84 24 68 01 00 	mov    rax,QWORD PTR [rsp+0x168]
 2af7441:	00
 2af7442:	48 85 c0             	test   rax,rax
 2af7445:	74 1c                	je     2af7463 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250fcd>
 2af7447:	4c 8b b4 24 60 01 00 	mov    r14,QWORD PTR [rsp+0x160]
 2af744e:	00
 2af744f:	48 83 f8 01          	cmp    rax,0x1
 2af7453:	0f 85 ee 00 00 00    	jne    2af7547 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250ee9>
 2af7459:	49 8b 06             	mov    rax,QWORD PTR [r14]
 2af745c:	48 89 83 d0 02 00 00 	mov    QWORD PTR [rbx+0x2d0],rax
 2af7463:	48 8b 84 24 80 01 00 	mov    rax,QWORD PTR [rsp+0x180]
 2af746a:	00
 2af746b:	48 85 c0             	test   rax,rax
 2af746e:	74 7e                	je     2af74ee <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250f42>
 2af7470:	48 89 5c 24 60       	mov    QWORD PTR [rsp+0x60],rbx
 2af7475:	4c 8b bc 24 78 01 00 	mov    r15,QWORD PTR [rsp+0x178]
 2af747c:	00
 2af747d:	48 83 f8 01          	cmp    rax,0x1
 2af7481:	74 57                	je     2af74da <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250f56>
 2af7483:	49 8d 6f 40          	lea    rbp,[r15+0x40]
 2af7487:	48 ff c8             	dec    rax
 2af748a:	48 bb ff ff ff ff ff 	movabs rbx,0x3ffffffffffffff
 2af7491:	ff ff 03
 2af7494:	48 21 c3             	and    rbx,rax
 2af7497:	4c 8d 64 24 07       	lea    r12,[rsp+0x7]
 2af749c:	4c 8d 6c 24 10       	lea    r13,[rsp+0x10]
 2af74a1:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
 2af74a8:	00
 2af74a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 2af74b0:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 2af74b5:	48 89 ac 24 80 00 00 	mov    QWORD PTR [rsp+0x80],rbp
 2af74bc:	00
 2af74bd:	4c 89 e7             	mov    rdi,r12
 2af74c0:	4c 89 ee             	mov    rsi,r13
 2af74c3:	4c 89 f2             	mov    rdx,r14
 2af74c6:	e8 b5 03 bb ff       	call   26a7880 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x36a0bb0>
 2af74cb:	84 c0                	test   al,al
 2af74cd:	4c 0f 4e fd          	cmovle r15,rbp
 2af74d1:	48 83 c5 40          	add    rbp,0x40
 2af74d5:	48 ff cb             	dec    rbx
 2af74d8:	75 d6                	jne    2af74b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250f80>
 2af74da:	49 8b 07             	mov    rax,QWORD PTR [r15]
 2af74dd:	48 8b 5c 24 60       	mov    rbx,QWORD PTR [rsp+0x60]
 2af74e2:	48 89 83 d8 02 00 00 	mov    QWORD PTR [rbx+0x2d8],rax
 2af74e9:	48 8b 6c 24 08       	mov    rbp,QWORD PTR [rsp+0x8]
 2af74ee:	4c 8b 7d 00          	mov    r15,QWORD PTR [rbp+0x0]
 2af74f2:	b8 01 00 00 00       	mov    eax,0x1
 2af74f7:	45 31 e4             	xor    r12d,r12d
 2af74fa:	4d 3b a7 e0 38 00 00 	cmp    r12,QWORD PTR [r15+0x38e0]
 2af7501:	0f 80 67 01 00 00    	jo     2af766e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250dc2>
 2af7507:	4d 8b a7 f0 38 00 00 	mov    r12,QWORD PTR [r15+0x38f0]
 2af750e:	4d 85 e4             	test   r12,r12
 2af7511:	0f 84 7f 00 00 00    	je     2af7596 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250e9a>
 2af7517:	4d 8b af e8 38 00 00 	mov    r13,QWORD PTR [r15+0x38e8]
 2af751e:	4f 8d 34 a4          	lea    r14,[r12+r12*4]
 2af7522:	4c 89 f7             	mov    rdi,r14
 2af7525:	ff 15 55 7f 9e 03    	call   QWORD PTR [rip+0x39e7f55]        # 64df480 <__register_atfork@plt+0xed8f0>
 2af752b:	48 85 c0             	test   rax,rax
 2af752e:	0f 84 76 02 00 00    	je     2af77aa <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250c86>
 2af7534:	44 89 e1             	mov    ecx,r12d
 2af7537:	83 e1 03             	and    ecx,0x3
 2af753a:	49 83 fc 04          	cmp    r12,0x4
 2af753e:	73 5e                	jae    2af759e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250e92>
 2af7540:	31 d2                	xor    edx,edx
 2af7542:	e9 e0 00 00 00       	jmp    2af7627 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250e09>
 2af7547:	4d 8d 7e 20          	lea    r15,[r14+0x20]
 2af754b:	48 ff c8             	dec    rax
 2af754e:	49 bc ff ff ff ff ff 	movabs r12,0x7ffffffffffffff
 2af7555:	ff ff 07
 2af7558:	49 21 c4             	and    r12,rax
 2af755b:	eb 10                	jmp    2af756d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250ec3>
 2af755d:	0f 1f 00             	nop    DWORD PTR [rax]
 2af7560:	49 83 c7 20          	add    r15,0x20
 2af7564:	49 ff cc             	dec    r12
 2af7567:	0f 84 ec fe ff ff    	je     2af7459 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250fd7>
 2af756d:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
 2af7570:	49 8b 17             	mov    rdx,QWORD PTR [r15]
 2af7573:	48 39 d1             	cmp    rcx,rdx
 2af7576:	0f 97 c0             	seta   al
 2af7579:	1c 00                	sbb    al,0x0
 2af757b:	48 39 d1             	cmp    rcx,rdx
 2af757e:	75 0d                	jne    2af758d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250ea3>
 2af7580:	49 8d 7e 08          	lea    rdi,[r14+0x8]
 2af7584:	49 8d 77 08          	lea    rsi,[r15+0x8]
 2af7588:	e8 33 a1 83 ff       	call   23316c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3a16d70>
 2af758d:	84 c0                	test   al,al
 2af758f:	7f cf                	jg     2af7560 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250ed0>
 2af7591:	4d 89 fe             	mov    r14,r15
 2af7594:	eb ca                	jmp    2af7560 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250ed0>
 2af7596:	45 31 e4             	xor    r12d,r12d
 2af7599:	e9 d0 00 00 00       	jmp    2af766e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250dc2>
 2af759e:	4c 89 e6             	mov    rsi,r12
 2af75a1:	48 83 e6 fc          	and    rsi,0xfffffffffffffffc
 2af75a5:	49 8d bd 35 01 00 00 	lea    rdi,[r13+0x135]
 2af75ac:	31 d2                	xor    edx,edx
 2af75ae:	49 89 c0             	mov    r8,rax
 2af75b1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 2af75b8:	0f 1f 84 00 00 00 00
 2af75bf:	00
 2af75c0:	44 8b 8f 10 ff ff ff 	mov    r9d,DWORD PTR [rdi-0xf0]
 2af75c7:	44 0f b6 97 14 ff ff 	movzx  r10d,BYTE PTR [rdi-0xec]
 2af75ce:	ff
 2af75cf:	45 88 50 04          	mov    BYTE PTR [r8+0x4],r10b
 2af75d3:	45 89 08             	mov    DWORD PTR [r8],r9d
 2af75d6:	44 8b 8f 60 ff ff ff 	mov    r9d,DWORD PTR [rdi-0xa0]
 2af75dd:	44 0f b6 97 64 ff ff 	movzx  r10d,BYTE PTR [rdi-0x9c]
 2af75e4:	ff
 2af75e5:	45 88 50 09          	mov    BYTE PTR [r8+0x9],r10b
 2af75e9:	45 89 48 05          	mov    DWORD PTR [r8+0x5],r9d
 2af75ed:	44 8b 4f b0          	mov    r9d,DWORD PTR [rdi-0x50]
 2af75f1:	44 0f b6 57 b4       	movzx  r10d,BYTE PTR [rdi-0x4c]
 2af75f6:	45 88 50 0e          	mov    BYTE PTR [r8+0xe],r10b
 2af75fa:	45 89 48 0a          	mov    DWORD PTR [r8+0xa],r9d
 2af75fe:	44 8b 0f             	mov    r9d,DWORD PTR [rdi]
 2af7601:	44 0f b6 57 04       	movzx  r10d,BYTE PTR [rdi+0x4]
 2af7606:	45 88 50 13          	mov    BYTE PTR [r8+0x13],r10b
 2af760a:	45 89 48 0f          	mov    DWORD PTR [r8+0xf],r9d
 2af760e:	48 83 c2 04          	add    rdx,0x4
 2af7612:	48 81 c7 40 01 00 00 	add    rdi,0x140
 2af7619:	49 83 c0 14          	add    r8,0x14
 2af761d:	48 39 d6             	cmp    rsi,rdx
 2af7620:	75 9e                	jne    2af75c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250e70>
 2af7622:	48 85 c9             	test   rcx,rcx
 2af7625:	74 47                	je     2af766e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250dc2>
 2af7627:	48 8d 34 92          	lea    rsi,[rdx+rdx*4]
 2af762b:	48 89 c2             	mov    rdx,rax
 2af762e:	48 01 f2             	add    rdx,rsi
 2af7631:	48 c1 e6 04          	shl    rsi,0x4
 2af7635:	4c 01 ee             	add    rsi,r13
 2af7638:	48 83 c6 45          	add    rsi,0x45
 2af763c:	c1 e1 04             	shl    ecx,0x4
 2af763f:	48 8d 0c 89          	lea    rcx,[rcx+rcx*4]
 2af7643:	31 ff                	xor    edi,edi
 2af7645:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
 2af764c:	00 00 00 00
 2af7650:	44 8b 04 3e          	mov    r8d,DWORD PTR [rsi+rdi*1]
 2af7654:	44 0f b6 4c 3e 04    	movzx  r9d,BYTE PTR [rsi+rdi*1+0x4]
 2af765a:	44 88 4a 04          	mov    BYTE PTR [rdx+0x4],r9b
 2af765e:	44 89 02             	mov    DWORD PTR [rdx],r8d
 2af7661:	48 83 c2 05          	add    rdx,0x5
 2af7665:	48 83 c7 50          	add    rdi,0x50
 2af7669:	48 39 f9             	cmp    rcx,rdi
 2af766c:	75 e2                	jne    2af7650 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250de0>
 2af766e:	49 8b 8f f8 38 00 00 	mov    rcx,QWORD PTR [r15+0x38f8]
 2af7675:	4c 89 a4 24 38 01 00 	mov    QWORD PTR [rsp+0x138],r12
 2af767c:	00
 2af767d:	48 89 84 24 40 01 00 	mov    QWORD PTR [rsp+0x140],rax
 2af7684:	00
 2af7685:	4c 89 a4 24 48 01 00 	mov    QWORD PTR [rsp+0x148],r12
 2af768c:	00
 2af768d:	48 89 8c 24 50 01 00 	mov    QWORD PTR [rsp+0x150],rcx
 2af7694:	00
 2af7695:	48 8b bb c8 02 00 00 	mov    rdi,QWORD PTR [rbx+0x2c8]
 2af769c:	48 83 c7 10          	add    rdi,0x10
 2af76a0:	48 8d 15 e9 0a 95 03 	lea    rdx,[rip+0x3950ae9]        # 6448190 <__register_atfork@plt+0x56600>
 2af76a7:	48 8d b4 24 38 01 00 	lea    rsi,[rsp+0x138]
 2af76ae:	00
 2af76af:	e8 bc ac a0 ff       	call   2502370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x38460c0>
 2af76b4:	4c 8d b3 a0 02 00 00 	lea    r14,[rbx+0x2a0]
 2af76bb:	4c 8d bc 24 80 00 00 	lea    r15,[rsp+0x80]
 2af76c2:	00
 2af76c3:	48 8d b4 24 58 01 00 	lea    rsi,[rsp+0x158]
 2af76ca:	00
 2af76cb:	ba b0 00 00 00       	mov    edx,0xb0
 2af76d0:	4c 89 ff             	mov    rdi,r15
 2af76d3:	ff 15 2f 7e 9e 03    	call   QWORD PTR [rip+0x39e7e2f]        # 64df508 <__register_atfork@plt+0xed978>
 2af76d9:	48 8d 15 c8 0a 95 03 	lea    rdx,[rip+0x3950ac8]        # 64481a8 <__register_atfork@plt+0x56618>
 2af76e0:	4c 89 f7             	mov    rdi,r14
 2af76e3:	4c 89 fe             	mov    rsi,r15
 2af76e6:	e8 65 65 1f 00       	call   2cedc50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x305a7e0>
 2af76eb:	bf 01 00 00 00       	mov    edi,0x1
 2af76f0:	e8 eb cb 18 03       	call   5c842e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4150>
 2af76f5:	48 89 44 24 70       	mov    QWORD PTR [rsp+0x70],rax
 2af76fa:	89 54 24 78          	mov    DWORD PTR [rsp+0x78],edx
 2af76fe:	48 8b 44 24 68       	mov    rax,QWORD PTR [rsp+0x68]
 2af7703:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 2af7708:	8b 44 24 2c          	mov    eax,DWORD PTR [rsp+0x2c]
 2af770c:	89 44 24 18          	mov    DWORD PTR [rsp+0x18],eax
 2af7710:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
 2af7717:	00
 2af7718:	48 8d 74 24 70       	lea    rsi,[rsp+0x70]
 2af771d:	48 8d 54 24 10       	lea    rdx,[rsp+0x10]
 2af7722:	e8 e9 ca 18 03       	call   5c84210 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4220>
 2af7727:	80 bc 24 80 00 00 00 	cmp    BYTE PTR [rsp+0x80],0x0
 2af772e:	00
 2af772f:	66 0f 57 c0          	xorpd  xmm0,xmm0
 2af7733:	66 0f 57 c9          	xorpd  xmm1,xmm1
 2af7737:	75 3c                	jne    2af7775 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250cbb>
 2af7739:	f2 0f 10 94 24 88 00 	movsd  xmm2,QWORD PTR [rsp+0x88]
 2af7740:	00 00
 2af7742:	0f 57 c9             	xorps  xmm1,xmm1
 2af7745:	f2 0f 2a 8c 24 90 00 	cvtsi2sd xmm1,DWORD PTR [rsp+0x90]
 2af774c:	00 00
 2af774e:	0f 14 15 bb 9a 95 fd 	unpcklps xmm2,XMMWORD PTR [rip+0xfffffffffd959abb]        # 451210 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f7220>
 2af7755:	66 0f 5c 15 13 8a 95 	subpd  xmm2,XMMWORD PTR [rip+0xfffffffffd958a13]        # 450170 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f82c0>
 2af775c:	fd
 2af775d:	66 0f 28 da          	movapd xmm3,xmm2
 2af7761:	66 0f 15 da          	unpckhpd xmm3,xmm2
 2af7765:	f2 0f 58 da          	addsd  xmm3,xmm2
 2af7769:	f2 0f 5e 0d df 15 96 	divsd  xmm1,QWORD PTR [rip+0xfffffffffd9615df]        # 458d50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef6e0>
 2af7770:	fd
 2af7771:	f2 0f 58 cb          	addsd  xmm1,xmm3
 2af7775:	66 0f 2e 0d 93 18 96 	ucomisd xmm1,QWORD PTR [rip+0xfffffffffd961893]        # 459010 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef420>
 2af777c:	fd
 2af777d:	74 04                	je     2af7783 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250cad>
 2af777f:	66 0f 28 c1          	movapd xmm0,xmm1
 2af7783:	48 8d 15 36 0a 95 03 	lea    rdx,[rip+0x3950a36]        # 64481c0 <__register_atfork@plt+0x56630>
 2af778a:	be 01 00 00 00       	mov    esi,0x1
 2af778f:	48 89 df             	mov    rdi,rbx
 2af7792:	ff 15 78 98 9e 03    	call   QWORD PTR [rip+0x39e9878]        # 64e1010 <__register_atfork@plt+0xef480>
 2af7798:	48 81 c4 08 02 00 00 	add    rsp,0x208
 2af779f:	5b                   	pop    rbx
 2af77a0:	41 5c                	pop    r12
 2af77a2:	41 5d                	pop    r13
 2af77a4:	41 5e                	pop    r14
 2af77a6:	41 5f                	pop    r15
 2af77a8:	5d                   	pop    rbp
 2af77a9:	c3                   	ret
 2af77aa:	bf 01 00 00 00       	mov    edi,0x1
 2af77af:	4c 89 f6             	mov    rsi,r14
 2af77b2:	ff 15 e0 7c 9e 03    	call   QWORD PTR [rip+0x39e7ce0]        # 64df498 <__register_atfork@plt+0xed908>
 2af77b8:	0f 0b                	ud2
 2af77ba:	48 89 c3             	mov    rbx,rax
 2af77bd:	48 8d bc 24 58 01 00 	lea    rdi,[rsp+0x158]
 2af77c4:	00
 2af77c5:	e8 46 0c fc ff       	call   2ab8410 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3290020>
 2af77ca:	eb 14                	jmp    2af77e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250c50>
 2af77cc:	eb 02                	jmp    2af77d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250c60>
 2af77ce:	eb 00                	jmp    2af77d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3250c60>
 2af77d0:	48 89 c3             	mov    rbx,rax
 2af77d3:	48 8d bc 24 58 01 00 	lea    rdi,[rsp+0x158]
 2af77da:	00
 2af77db:	e8 10 4c fc ff       	call   2abc3f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x328c040>
 2af77e0:	48 89 df             	mov    rdi,rbx
 2af77e3:	e8 68 92 8f 03       	call   63f0a50 <_Unwind_Resume@plt>
 2af77e8:	ff 15 d2 7c 9e 03    	call   QWORD PTR [rip+0x39e7cd2]        # 64df4c0 <__register_atfork@plt+0xed930>
