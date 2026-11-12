
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000032b03e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a98050>:
 32b03e0:	55                   	push   rbp
 32b03e1:	41 57                	push   r15
 32b03e3:	41 56                	push   r14
 32b03e5:	41 55                	push   r13
 32b03e7:	41 54                	push   r12
 32b03e9:	53                   	push   rbx
 32b03ea:	48 81 ec d8 00 00 00 	sub    rsp,0xd8
 32b03f1:	48 89 fb             	mov    rbx,rdi
 32b03f4:	0f b6 46 20          	movzx  eax,BYTE PTR [rsi+0x20]
 32b03f8:	0f b6 7e 21          	movzx  edi,BYTE PTR [rsi+0x21]
 32b03fc:	c6 46 20 01          	mov    BYTE PTR [rsi+0x20],0x1
 32b0400:	3c 01                	cmp    al,0x1
 32b0402:	75 5e                	jne    32b0462 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97fce>
 32b0404:	48 8b 4e 18          	mov    rcx,QWORD PTR [rsi+0x18]
 32b0408:	48 85 c9             	test   rcx,rcx
 32b040b:	74 1e                	je     32b042b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a98005>
 32b040d:	48 8b 7e 10          	mov    rdi,QWORD PTR [rsi+0x10]
 32b0411:	48 ff c9             	dec    rcx
 32b0414:	0f b6 07             	movzx  eax,BYTE PTR [rdi]
 32b0417:	48 ff c7             	inc    rdi
 32b041a:	48 89 7e 10          	mov    QWORD PTR [rsi+0x10],rdi
 32b041e:	48 89 4e 18          	mov    QWORD PTR [rsi+0x18],rcx
 32b0422:	84 c0                	test   al,al
 32b0424:	78 0d                	js     32b0433 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97ffd>
 32b0426:	45 31 c0             	xor    r8d,r8d
 32b0429:	eb 51                	jmp    32b047c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97fb4>
 32b042b:	c6 03 00             	mov    BYTE PTR [rbx],0x0
 32b042e:	e9 3c 0b 00 00       	jmp    32b0f6f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a974c1>
 32b0433:	41 b0 e0             	mov    r8b,0xe0
 32b0436:	3c df                	cmp    al,0xdf
 32b0438:	77 42                	ja     32b047c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97fb4>
 32b043a:	3c 90                	cmp    al,0x90
 32b043c:	73 09                	jae    32b0447 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97fe9>
 32b043e:	24 0f                	and    al,0xf
 32b0440:	89 c7                	mov    edi,eax
 32b0442:	e9 95 00 00 00       	jmp    32b04dc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97f54>
 32b0447:	3c a0                	cmp    al,0xa0
 32b0449:	73 09                	jae    32b0454 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97fdc>
 32b044b:	24 0f                	and    al,0xf
 32b044d:	89 c7                	mov    edi,eax
 32b044f:	e9 eb 08 00 00       	jmp    32b0d3f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a976f1>
 32b0454:	89 c7                	mov    edi,eax
 32b0456:	40 80 e7 1f          	and    dil,0x1f
 32b045a:	3c c0                	cmp    al,0xc0
 32b045c:	0f 82 66 0a 00 00    	jb     32b0ec8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97568>
 32b0462:	44 0f b6 c0          	movzx  r8d,al
 32b0466:	48 8d 0d a3 7b 46 fd 	lea    rcx,[rip+0xfffffffffd467ba3]        # 718010 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5630420>
 32b046d:	4e 63 0c 81          	movsxd r9,DWORD PTR [rcx+r8*4]
 32b0471:	49 01 c9             	add    r9,rcx
 32b0474:	41 ff e1             	jmp    r9
 32b0477:	41 89 c0             	mov    r8d,eax
 32b047a:	89 f8                	mov    eax,edi
 32b047c:	41 0f b6 d0          	movzx  edx,r8b
 32b0480:	0f b6 c8             	movzx  ecx,al
 32b0483:	48 89 df             	mov    rdi,rbx
 32b0486:	ff 15 e4 32 23 03    	call   QWORD PTR [rip+0x32332e4]        # 64e3770 <__register_atfork@plt+0xf1be0>
 32b048c:	e9 2c 10 00 00       	jmp    32b14bd <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a96f73>
 32b0491:	b1 02                	mov    cl,0x2
 32b0493:	41 81 c0 39 ff ff ff 	add    r8d,0xffffff39
 32b049a:	41 83 f8 11          	cmp    r8d,0x11
 32b049e:	0f 87 7f 0b 00 00    	ja     32b1023 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a9740d>
 32b04a4:	48 8d 15 e9 7e 46 fd 	lea    rdx,[rip+0xfffffffffd467ee9]        # 718394 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x563009c>
 32b04ab:	4e 63 04 82          	movsxd r8,DWORD PTR [rdx+r8*4]
 32b04af:	49 01 d0             	add    r8,rdx
 32b04b2:	41 ff e0             	jmp    r8
 32b04b5:	48 8b 4e 18          	mov    rcx,QWORD PTR [rsi+0x18]
 32b04b9:	48 85 c9             	test   rcx,rcx
 32b04bc:	0f 84 5f 0b 00 00    	je     32b1021 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a9740f>
 32b04c2:	48 8b 56 10          	mov    rdx,QWORD PTR [rsi+0x10]
 32b04c6:	48 ff c9             	dec    rcx
 32b04c9:	0f b6 02             	movzx  eax,BYTE PTR [rdx]
 32b04cc:	48 ff c2             	inc    rdx
 32b04cf:	48 89 56 10          	mov    QWORD PTR [rsi+0x10],rdx
 32b04d3:	48 89 4e 18          	mov    QWORD PTR [rsi+0x18],rcx
 32b04d7:	e9 3f 0c 00 00       	jmp    32b111b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97315>
 32b04dc:	44 0f b6 ef          	movzx  r13d,dil
 32b04e0:	0f b7 46 22          	movzx  eax,WORD PTR [rsi+0x22]
 32b04e4:	66 85 c0             	test   ax,ax
 32b04e7:	0f 84 35 12 00 00    	je     32b1722 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a96d0e>
 32b04ed:	66 ff c8             	dec    ax
 32b04f0:	66 89 46 22          	mov    WORD PTR [rsi+0x22],ax
 32b04f4:	0f 84 37 0c 00 00    	je     32b1131 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a972ff>
 32b04fa:	45 31 f6             	xor    r14d,r14d
 32b04fd:	45 85 ed             	test   r13d,r13d
 32b0500:	0f 84 24 0d 00 00    	je     32b122a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97206>
 32b0506:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
 32b050b:	4c 8b 3d 66 32 23 03 	mov    r15,QWORD PTR [rip+0x3233266]        # 64e3778 <__register_atfork@plt+0xf1be8>
 32b0512:	48 c7 84 24 88 00 00 	mov    QWORD PTR [rsp+0x88],0x0
 32b0519:	00 00 00 00 00
 32b051e:	48 c7 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],0x0
 32b0525:	00 00 00 00 00
 32b052a:	eb 29                	jmp    32b0555 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97edb>
 32b052c:	48 89 e7             	mov    rdi,rsp
 32b052f:	49 89 f4             	mov    r12,rsi
 32b0532:	ba 01 00 00 00       	mov    edx,0x1
 32b0537:	e8 14 59 f2 ff       	call   31d5e50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2b725e0>
 32b053c:	80 3c 24 09          	cmp    BYTE PTR [rsp],0x9
 32b0540:	0f 85 93 0d 00 00    	jne    32b12d9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97157>
 32b0546:	41 ff c6             	inc    r14d
 32b0549:	45 39 f5             	cmp    r13d,r14d
 32b054c:	4c 89 e6             	mov    rsi,r12
 32b054f:	0f 84 44 0c 00 00    	je     32b1199 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97297>
 32b0555:	0f b6 4e 20          	movzx  ecx,BYTE PTR [rsi+0x20]
 32b0559:	0f b6 7e 21          	movzx  edi,BYTE PTR [rsi+0x21]
 32b055d:	c6 46 20 01          	mov    BYTE PTR [rsi+0x20],0x1
 32b0561:	80 f9 01             	cmp    cl,0x1
 32b0564:	75 64                	jne    32b05ca <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97e66>
 32b0566:	48 8b 46 18          	mov    rax,QWORD PTR [rsi+0x18]
 32b056a:	48 85 c0             	test   rax,rax
 32b056d:	0f 84 a4 0c 00 00    	je     32b1217 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97219>
 32b0573:	48 8b 56 10          	mov    rdx,QWORD PTR [rsi+0x10]
 32b0577:	48 ff c8             	dec    rax
 32b057a:	0f b6 0a             	movzx  ecx,BYTE PTR [rdx]
 32b057d:	48 ff c2             	inc    rdx
 32b0580:	48 89 56 10          	mov    QWORD PTR [rsi+0x10],rdx
 32b0584:	48 89 46 18          	mov    QWORD PTR [rsi+0x18],rax
 32b0588:	84 c9                	test   cl,cl
 32b058a:	78 04                	js     32b0590 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97ea0>
 32b058c:	31 d2                	xor    edx,edx
 32b058e:	eb 51                	jmp    32b05e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97e4f>
 32b0590:	b2 e0                	mov    dl,0xe0
 32b0592:	80 f9 df             	cmp    cl,0xdf
 32b0595:	77 4a                	ja     32b05e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97e4f>
 32b0597:	80 f9 90             	cmp    cl,0x90
 32b059a:	73 0d                	jae    32b05a9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97e87>
 32b059c:	49 89 ef             	mov    r15,rbp
 32b059f:	80 e1 0f             	and    cl,0xf
 32b05a2:	89 cf                	mov    edi,ecx
 32b05a4:	e9 a4 03 00 00       	jmp    32b094d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97ae3>
 32b05a9:	80 f9 a0             	cmp    cl,0xa0
 32b05ac:	73 0d                	jae    32b05bb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97e75>
 32b05ae:	49 89 ef             	mov    r15,rbp
 32b05b1:	80 e1 0f             	and    cl,0xf
 32b05b4:	89 cf                	mov    edi,ecx
 32b05b6:	e9 28 02 00 00       	jmp    32b07e3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97c4d>
 32b05bb:	89 cf                	mov    edi,ecx
 32b05bd:	40 80 e7 1f          	and    dil,0x1f
 32b05c1:	80 f9 c0             	cmp    cl,0xc0
 32b05c4:	0f 82 92 02 00 00    	jb     32b085c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2a97bd4>
 32b05ca:	0f b6 d1             	movzx  edx,cl
 32b05cd:	4c 8d 05 08 7e 46 fd 	lea    r8,[rip+0xfffffffffd467e08]        # 7183dc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5630054>
 32b05d4:	49 63 04 90          	movsxd rax,DWORD PTR [r8+rdx*4]
 32b05d8:	4c 01 c0             	add    rax,r8
 32b05db:	ff e0                	jmp    rax
 32b05dd:	89 ca                	mov    edx,ecx
