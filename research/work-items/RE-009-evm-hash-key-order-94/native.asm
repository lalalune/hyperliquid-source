
artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000028546c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753740>:
 28546c0:	55                   	push   rbp
 28546c1:	41 57                	push   r15
 28546c3:	41 56                	push   r14
 28546c5:	41 55                	push   r13
 28546c7:	41 54                	push   r12
 28546c9:	53                   	push   rbx
 28546ca:	48 81 ec 98 00 00 00 	sub    rsp,0x98
 28546d1:	48 89 fb             	mov    rbx,rdi
 28546d4:	48 8b 06             	mov    rax,QWORD PTR [rsi]
 28546d7:	48 85 c0             	test   rax,rax
 28546da:	0f 84 f0 00 00 00    	je     28547d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753630>
 28546e0:	4c 8b 5e 08          	mov    r11,QWORD PTR [rsi+0x8]
 28546e4:	48 8b 7a 18          	mov    rdi,QWORD PTR [rdx+0x18]
 28546e8:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
 28546ec:	4c 8b 0a             	mov    r9,QWORD PTR [rdx]
 28546ef:	4c 8b 52 08          	mov    r10,QWORD PTR [rdx+0x8]
 28546f3:	44 0f b7 b8 ca 02 00 	movzx  r15d,WORD PTR [rax+0x2ca]
 28546fa:	00
 28546fb:	45 89 fc             	mov    r12d,r15d
 28546fe:	41 c1 e4 05          	shl    r12d,0x5
 2854702:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
 2854709:	45 31 ed             	xor    r13d,r13d
 285470c:	eb 1a                	jmp    2854728 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27536d8>
 285470e:	66 90                	xchg   ax,ax
 2854710:	4c 39 ed             	cmp    rbp,r13
 2854713:	40 0f 97 c5          	seta   bpl
 2854717:	40 80 dd 00          	sbb    bpl,0x0
 285471b:	4d 8d 6e 20          	lea    r13,[r14+0x20]
 285471f:	48 ff c2             	inc    rdx
 2854722:	40 80 fd 01          	cmp    bpl,0x1
 2854726:	75 48                	jne    2854770 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753690>
 2854728:	4d 39 ec             	cmp    r12,r13
 285472b:	74 53                	je     2854780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753680>
 285472d:	4d 89 ee             	mov    r14,r13
 2854730:	4e 8b 6c 28 18       	mov    r13,QWORD PTR [rax+r13*1+0x18]
 2854735:	48 89 fd             	mov    rbp,rdi
 2854738:	4c 39 ef             	cmp    rdi,r13
 285473b:	75 d3                	jne    2854710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27536f0>
 285473d:	4e 8b 6c 30 10       	mov    r13,QWORD PTR [rax+r14*1+0x10]
 2854742:	4c 89 c5             	mov    rbp,r8
 2854745:	4d 39 e8             	cmp    r8,r13
 2854748:	75 c6                	jne    2854710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27536f0>
 285474a:	4e 8b 6c 30 08       	mov    r13,QWORD PTR [rax+r14*1+0x8]
 285474f:	4c 89 d5             	mov    rbp,r10
 2854752:	4d 39 ea             	cmp    r10,r13
 2854755:	75 b9                	jne    2854710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27536f0>
 2854757:	4e 8b 2c 30          	mov    r13,QWORD PTR [rax+r14*1]
 285475b:	4c 89 cd             	mov    rbp,r9
 285475e:	4d 39 e9             	cmp    r9,r13
 2854761:	75 ad                	jne    2854710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27536f0>
 2854763:	eb 31                	jmp    2854796 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275366a>
 2854765:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
 285476c:	00 00 00 00
 2854770:	40 0f b6 ed          	movzx  ebp,bpl
 2854774:	85 ed                	test   ebp,ebp
 2854776:	74 1e                	je     2854796 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275366a>
 2854778:	eb 09                	jmp    2854783 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275367d>
 285477a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
 2854780:	4c 89 fa             	mov    rdx,r15
 2854783:	49 83 eb 01          	sub    r11,0x1
 2854787:	72 58                	jb     28547e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275361f>
 2854789:	48 8b 84 d0 d0 02 00 	mov    rax,QWORD PTR [rax+rdx*8+0x2d0]
 2854790:	00
 2854791:	e9 5d ff ff ff       	jmp    28546f3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275370d>
 2854796:	42 0f 10 84 30 60 01 	movups xmm0,XMMWORD PTR [rax+r14*1+0x160]
 285479d:	00 00
 285479f:	42 0f 10 8c 30 70 01 	movups xmm1,XMMWORD PTR [rax+r14*1+0x170]
 28547a6:	00 00
 28547a8:	0f 11 4b 11          	movups XMMWORD PTR [rbx+0x11],xmm1
 28547ac:	0f 11 43 01          	movups XMMWORD PTR [rbx+0x1],xmm0
 28547b0:	0f 10 01             	movups xmm0,XMMWORD PTR [rcx]
 28547b3:	0f 10 49 10          	movups xmm1,XMMWORD PTR [rcx+0x10]
 28547b7:	42 0f 11 84 30 60 01 	movups XMMWORD PTR [rax+r14*1+0x160],xmm0
 28547be:	00 00
 28547c0:	42 0f 11 8c 30 70 01 	movups XMMWORD PTR [rax+r14*1+0x170],xmm1
 28547c7:	00 00
 28547c9:	b0 01                	mov    al,0x1
 28547cb:	e9 20 01 00 00       	jmp    28548f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753510>
 28547d0:	4c 8b 0a             	mov    r9,QWORD PTR [rdx]
 28547d3:	4c 8b 52 08          	mov    r10,QWORD PTR [rdx+0x8]
 28547d7:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
 28547db:	48 8b 7a 18          	mov    rdi,QWORD PTR [rdx+0x18]
 28547df:	31 c0                	xor    eax,eax
 28547e1:	48 89 34 24          	mov    QWORD PTR [rsp],rsi
 28547e5:	4c 8d 74 24 08       	lea    r14,[rsp+0x8]
 28547ea:	4c 89 4c 24 08       	mov    QWORD PTR [rsp+0x8],r9
 28547ef:	4c 89 54 24 10       	mov    QWORD PTR [rsp+0x10],r10
 28547f4:	4c 89 44 24 18       	mov    QWORD PTR [rsp+0x18],r8
 28547f9:	48 89 7c 24 20       	mov    QWORD PTR [rsp+0x20],rdi
 28547fe:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 2854803:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
 285480a:	00 00
 285480c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
 2854811:	48 85 c0             	test   rax,rax
 2854814:	74 51                	je     2854867 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753599>
 2854816:	48 8d 44 24 28       	lea    rax,[rsp+0x28]
 285481b:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
 285481f:	48 89 54 24 50       	mov    QWORD PTR [rsp+0x50],rdx
 2854824:	0f 10 00             	movups xmm0,XMMWORD PTR [rax]
 2854827:	0f 29 44 24 40       	movaps XMMWORD PTR [rsp+0x40],xmm0
 285482c:	41 0f 10 06          	movups xmm0,XMMWORD PTR [r14]
 2854830:	41 0f 10 4e 10       	movups xmm1,XMMWORD PTR [r14+0x10]
 2854835:	0f 29 4c 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm1
 285483a:	0f 29 44 24 60       	movaps XMMWORD PTR [rsp+0x60],xmm0
 285483f:	4c 8d 4c 24 40       	lea    r9,[rsp+0x40]
 2854844:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
 285484b:	00
 285484c:	48 8d 74 24 40       	lea    rsi,[rsp+0x40]
 2854851:	48 8d 54 24 60       	lea    rdx,[rsp+0x60]
 2854856:	49 89 e0             	mov    r8,rsp
 2854859:	e8 c2 f4 25 ff       	call   1ab3d20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f40e0>
 285485e:	48 8b 0c 24          	mov    rcx,QWORD PTR [rsp]
 2854862:	e9 83 00 00 00       	jmp    28548ea <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753516>
 2854867:	49 89 f4             	mov    r12,rsi
 285486a:	49 89 cf             	mov    r15,rcx
 285486d:	bf d0 02 00 00       	mov    edi,0x2d0
 2854872:	ff 15 60 97 f1 02    	call   QWORD PTR [rip+0x2f19760]        # 576dfd8 <__register_atfork@plt+0x10cd98>
 2854878:	48 85 c0             	test   rax,rax
 285487b:	0f 84 86 00 00 00    	je     2854907 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27534f9>
 2854881:	48 c7 80 c0 02 00 00 	mov    QWORD PTR [rax+0x2c0],0x0
 2854888:	00 00 00 00
 285488c:	66 c7 80 ca 02 00 00 	mov    WORD PTR [rax+0x2ca],0x0
 2854893:	00 00
 2854895:	49 89 04 24          	mov    QWORD PTR [r12],rax
 2854899:	49 c7 44 24 08 00 00 	mov    QWORD PTR [r12+0x8],0x0
 28548a0:	00 00
 28548a2:	0f b7 90 ca 02 00 00 	movzx  edx,WORD PTR [rax+0x2ca]
 28548a9:	48 83 fa 0b          	cmp    rdx,0xb
 28548ad:	73 68                	jae    2854917 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x27534e9>
 28548af:	4c 89 e1             	mov    rcx,r12
 28548b2:	8d 72 01             	lea    esi,[rdx+0x1]
 28548b5:	66 89 b0 ca 02 00 00 	mov    WORD PTR [rax+0x2ca],si
 28548bc:	c1 e2 05             	shl    edx,0x5
 28548bf:	41 0f 10 06          	movups xmm0,XMMWORD PTR [r14]
 28548c3:	41 0f 10 4e 10       	movups xmm1,XMMWORD PTR [r14+0x10]
 28548c8:	0f 11 4c 10 10       	movups XMMWORD PTR [rax+rdx*1+0x10],xmm1
 28548cd:	0f 11 04 10          	movups XMMWORD PTR [rax+rdx*1],xmm0
 28548d1:	41 0f 10 07          	movups xmm0,XMMWORD PTR [r15]
 28548d5:	41 0f 10 4f 10       	movups xmm1,XMMWORD PTR [r15+0x10]
 28548da:	0f 11 84 10 60 01 00 	movups XMMWORD PTR [rax+rdx*1+0x160],xmm0
 28548e1:	00
 28548e2:	0f 11 8c 10 70 01 00 	movups XMMWORD PTR [rax+rdx*1+0x170],xmm1
 28548e9:	00
 28548ea:	48 ff 41 10          	inc    QWORD PTR [rcx+0x10]
 28548ee:	31 c0                	xor    eax,eax
 28548f0:	88 03                	mov    BYTE PTR [rbx],al
 28548f2:	48 89 d8             	mov    rax,rbx
 28548f5:	48 81 c4 98 00 00 00 	add    rsp,0x98
 28548fc:	5b                   	pop    rbx
 28548fd:	41 5c                	pop    r12
 28548ff:	41 5d                	pop    r13
 2854901:	41 5e                	pop    r14
 2854903:	41 5f                	pop    r15
 2854905:	5d                   	pop    rbp
 2854906:	c3                   	ret
 2854907:	bf 08 00 00 00       	mov    edi,0x8
 285490c:	be d0 02 00 00       	mov    esi,0x2d0
 2854911:	ff 15 09 97 f1 02    	call   QWORD PTR [rip+0x2f19709]        # 576e020 <__register_atfork@plt+0x10cde0>
 2854917:	48 8d 3d 42 81 9b fd 	lea    rdi,[rip+0xfffffffffd9b8142]        # 20ca60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4d9b3a0>
 285491e:	48 8d 15 13 3b e3 02 	lea    rdx,[rip+0x2e33b13]        # 5688438 <__register_atfork@plt+0x271f8>
 2854925:	be 20 00 00 00       	mov    esi,0x20
 285492a:	ff 15 d8 97 f1 02    	call   QWORD PTR [rip+0x2f197d8]        # 576e108 <__register_atfork@plt+0x10cec8>
