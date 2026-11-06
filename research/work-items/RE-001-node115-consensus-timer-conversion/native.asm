
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004eca5d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7de60>:
 4eca5d0:	41 57                	push   r15
 4eca5d2:	41 56                	push   r14
 4eca5d4:	53                   	push   rbx
 4eca5d5:	48 81 ec 80 00 00 00 	sub    rsp,0x80
 4eca5dc:	45 31 ff             	xor    r15d,r15d
 4eca5df:	66 0f 57 c9          	xorpd  xmm1,xmm1
 4eca5e3:	66 0f 2e c8          	ucomisd xmm1,xmm0
 4eca5e7:	0f 87 f0 01 00 00    	ja     4eca7dd <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dc53>
 4eca5ed:	48 89 fb             	mov    rbx,rdi
 4eca5f0:	66 48 0f 7e c0       	movq   rax,xmm0
 4eca5f5:	48 89 c1             	mov    rcx,rax
 4eca5f8:	48 c1 e9 34          	shr    rcx,0x34
 4eca5fc:	81 e1 ff 07 00 00    	and    ecx,0x7ff
 4eca602:	81 f9 e0 03 00 00    	cmp    ecx,0x3e0
 4eca608:	73 08                	jae    4eca612 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7de1e>
 4eca60a:	45 31 f6             	xor    r14d,r14d
 4eca60d:	e9 31 01 00 00       	jmp    4eca743 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dced>
 4eca612:	48 bf ff ff ff ff ff 	movabs rdi,0xfffffffffffff
 4eca619:	ff 0f 00
 4eca61c:	48 89 c2             	mov    rdx,rax
 4eca61f:	48 21 fa             	and    rdx,rdi
 4eca622:	4c 8d 34 3a          	lea    r14,[rdx+rdi*1]
 4eca626:	49 ff c6             	inc    r14
 4eca629:	0f b7 d1             	movzx  edx,cx
 4eca62c:	81 fa ff 03 00 00    	cmp    edx,0x3ff
 4eca632:	73 79                	jae    4eca6ad <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dd83>
 4eca634:	80 c1 2d             	add    cl,0x2d
 4eca637:	31 ff                	xor    edi,edi
 4eca639:	4c 0f a5 f7          	shld   rdi,r14,cl
 4eca63d:	31 f6                	xor    esi,esi
 4eca63f:	49 d3 e6             	shl    r14,cl
 4eca642:	f6 c1 40             	test   cl,0x40
 4eca645:	49 0f 45 fe          	cmovne rdi,r14
 4eca649:	4c 0f 45 f6          	cmovne r14,rsi
 4eca64d:	b9 00 ca 9a 3b       	mov    ecx,0x3b9aca00
 4eca652:	4c 89 f0             	mov    rax,r14
 4eca655:	48 f7 e1             	mul    rcx
 4eca658:	48 69 cf 00 ca 9a 3b 	imul   rcx,rdi,0x3b9aca00
 4eca65f:	48 01 ca             	add    rdx,rcx
 4eca662:	48 89 d1             	mov    rcx,rdx
 4eca665:	48 c1 e9 20          	shr    rcx,0x20
 4eca669:	41 bf 00 00 00 00    	mov    r15d,0x0
 4eca66f:	85 d2                	test   edx,edx
 4eca671:	79 20                	jns    4eca693 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dd9d>
 4eca673:	48 25 00 fe ff ff    	and    rax,0xfffffffffffffe00
 4eca679:	89 d2                	mov    edx,edx
 4eca67b:	bf 00 00 00 80       	mov    edi,0x80000000
 4eca680:	48 31 d7             	xor    rdi,rdx
 4eca683:	48 09 c7             	or     rdi,rax
 4eca686:	0f 95 c0             	setne  al
 4eca689:	08 c8                	or     al,cl
 4eca68b:	44 0f b6 f8          	movzx  r15d,al
 4eca68f:	41 83 e7 01          	and    r15d,0x1
 4eca693:	41 01 cf             	add    r15d,ecx
 4eca696:	45 31 f6             	xor    r14d,r14d
 4eca699:	41 81 ff 00 ca 9a 3b 	cmp    r15d,0x3b9aca00
 4eca6a0:	41 0f 94 c6          	sete   r14b
 4eca6a4:	44 0f 44 fe          	cmove  r15d,esi
 4eca6a8:	e9 96 00 00 00       	jmp    4eca743 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dced>
 4eca6ad:	81 fa 33 04 00 00    	cmp    edx,0x433
 4eca6b3:	73 7c                	jae    4eca731 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dcff>
 4eca6b5:	8d 91 01 fc ff ff    	lea    edx,[rcx-0x3ff]
 4eca6bb:	40 b6 33             	mov    sil,0x33
 4eca6be:	40 28 ce             	sub    sil,cl
 4eca6c1:	89 f1                	mov    ecx,esi
 4eca6c3:	49 d3 ee             	shr    r14,cl
 4eca6c6:	89 d1                	mov    ecx,edx
 4eca6c8:	48 d3 e0             	shl    rax,cl
 4eca6cb:	48 21 f8             	and    rax,rdi
 4eca6ce:	b9 00 ca 9a 3b       	mov    ecx,0x3b9aca00
 4eca6d3:	48 f7 e1             	mul    rcx
 4eca6d6:	c1 e2 0c             	shl    edx,0xc
 4eca6d9:	48 89 c6             	mov    rsi,rax
 4eca6dc:	48 c1 ee 34          	shr    rsi,0x34
 4eca6e0:	09 d6                	or     esi,edx
 4eca6e2:	31 c9                	xor    ecx,ecx
 4eca6e4:	48 0f ba e0 33       	bt     rax,0x33
 4eca6e9:	41 bf 00 00 00 00    	mov    r15d,0x0
 4eca6ef:	73 28                	jae    4eca719 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dd17>
 4eca6f1:	48 ba 00 fe ff ff ff 	movabs rdx,0xffffffffffe00
 4eca6f8:	ff 0f 00
 4eca6fb:	48 21 d0             	and    rax,rdx
 4eca6fe:	48 ba 00 00 00 00 00 	movabs rdx,0x8000000000000
 4eca705:	00 08 00
 4eca708:	48 39 d0             	cmp    rax,rdx
 4eca70b:	0f 95 c0             	setne  al
 4eca70e:	40 08 f0             	or     al,sil
 4eca711:	44 0f b6 f8          	movzx  r15d,al
 4eca715:	41 83 e7 01          	and    r15d,0x1
 4eca719:	41 01 f7             	add    r15d,esi
 4eca71c:	31 c0                	xor    eax,eax
 4eca71e:	41 81 ff 00 ca 9a 3b 	cmp    r15d,0x3b9aca00
 4eca725:	0f 94 c0             	sete   al
 4eca728:	44 0f 44 f9          	cmove  r15d,ecx
 4eca72c:	49 01 c6             	add    r14,rax
 4eca72f:	eb 12                	jmp    4eca743 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dced>
 4eca731:	81 fa 3f 04 00 00    	cmp    edx,0x43f
 4eca737:	0f 83 9d 00 00 00    	jae    4eca7da <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dc56>
 4eca73d:	80 c1 cd             	add    cl,0xcd
 4eca740:	49 d3 e6             	shl    r14,cl
 4eca743:	48 8d 0d ae 35 5d 01 	lea    rcx,[rip+0x15d35ae]        # 649dcf8 <__register_atfork@plt+0xac168>
 4eca74a:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 4eca74f:	4c 89 f6             	mov    rsi,r14
 4eca752:	44 89 fa             	mov    edx,r15d
 4eca755:	ff 15 45 6c 61 01    	call   QWORD PTR [rip+0x1616c45]        # 64e13a0 <__register_atfork@plt+0xef810>
 4eca75b:	bf 70 00 00 00       	mov    edi,0x70
 4eca760:	ff 15 1a 4d 61 01    	call   QWORD PTR [rip+0x1614d1a]        # 64df480 <__register_atfork@plt+0xed8f0>
 4eca766:	48 85 c0             	test   rax,rax
 4eca769:	74 5d                	je     4eca7c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xe7dc68>
 4eca76b:	0f 10 44 24 70       	movups xmm0,XMMWORD PTR [rsp+0x70]
 4eca770:	0f 11 40 60          	movups XMMWORD PTR [rax+0x60],xmm0
 4eca774:	0f 10 44 24 60       	movups xmm0,XMMWORD PTR [rsp+0x60]
 4eca779:	0f 11 40 50          	movups XMMWORD PTR [rax+0x50],xmm0
 4eca77d:	0f 10 44 24 50       	movups xmm0,XMMWORD PTR [rsp+0x50]
 4eca782:	0f 11 40 40          	movups XMMWORD PTR [rax+0x40],xmm0
 4eca786:	0f 10 44 24 10       	movups xmm0,XMMWORD PTR [rsp+0x10]
 4eca78b:	0f 10 4c 24 20       	movups xmm1,XMMWORD PTR [rsp+0x20]
 4eca790:	0f 10 54 24 30       	movups xmm2,XMMWORD PTR [rsp+0x30]
 4eca795:	0f 10 5c 24 40       	movups xmm3,XMMWORD PTR [rsp+0x40]
 4eca79a:	0f 11 58 30          	movups XMMWORD PTR [rax+0x30],xmm3
 4eca79e:	0f 11 50 20          	movups XMMWORD PTR [rax+0x20],xmm2
 4eca7a2:	0f 11 48 10          	movups XMMWORD PTR [rax+0x10],xmm1
 4eca7a6:	0f 11 00             	movups XMMWORD PTR [rax],xmm0
 4eca7a9:	4c 89 33             	mov    QWORD PTR [rbx],r14
 4eca7ac:	44 89 7b 08          	mov    DWORD PTR [rbx+0x8],r15d
 4eca7b0:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
 4eca7b4:	c6 43 18 00          	mov    BYTE PTR [rbx+0x18],0x0
 4eca7b8:	48 89 d8             	mov    rax,rbx
 4eca7bb:	48 81 c4 80 00 00 00 	add    rsp,0x80
 4eca7c2:	5b                   	pop    rbx
 4eca7c3:	41 5e                	pop    r14
 4eca7c5:	41 5f                	pop    r15
 4eca7c7:	c3                   	ret
 4eca7c8:	bf 08 00 00 00       	mov    edi,0x8
 4eca7cd:	be 70 00 00 00       	mov    esi,0x70
 4eca7d2:	ff 15 b8 4c 61 01    	call   QWORD PTR [rip+0x1614cb8]        # 64df490 <__register_atfork@plt+0xed900>
 4eca7d8:	0f 0b                	ud2
 4eca7da:	41 b7 01             	mov    r15b,0x1
 4eca7dd:	44 88 7c 24 0f       	mov    BYTE PTR [rsp+0xf],r15b
 4eca7e2:	48 8d 44 24 0f       	lea    rax,[rsp+0xf]
 4eca7e7:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 4eca7ec:	48 8b 05 b5 6b 61 01 	mov    rax,QWORD PTR [rip+0x1616bb5]        # 64e13a8 <__register_atfork@plt+0xef818>
 4eca7f3:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
 4eca7f8:	48 8d 3d 58 10 57 fb 	lea    rdi,[rip+0xfffffffffb571058]        # 43b857 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590cbd9>
 4eca7ff:	48 8d 15 3a 27 5d 01 	lea    rdx,[rip+0x15d273a]        # 649cf40 <__register_atfork@plt+0xab3b0>
 4eca806:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
 4eca80b:	ff 15 a7 4e 61 01    	call   QWORD PTR [rip+0x1614ea7]        # 64df6b8 <__register_atfork@plt+0xedb28>
 4eca811:	48 89 c3             	mov    rbx,rax
 4eca814:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 4eca819:	e8 62 64 f8 ff       	call   4e50c80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef77b0>
 4eca81e:	48 89 df             	mov    rdi,rbx
 4eca821:	e8 2a 62 52 01       	call   63f0a50 <_Unwind_Resume@plt>
 4eca826:	ff 15 94 4c 61 01    	call   QWORD PTR [rip+0x1614c94]        # 64df4c0 <__register_atfork@plt+0xed930>
