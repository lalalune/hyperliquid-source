
artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001ab40d6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3d2a>:
 1ab40d6:	49 8b 87 c0 02 00 00 	mov    rax,QWORD PTR [r15+0x2c0]
 1ab40dd:	48 85 c0             	test   rax,rax
 1ab40e0:	0f 84 f9 04 00 00    	je     1ab45df <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3821>

artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001ab45df <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3821>:
 1ab45df:	45 31 ed             	xor    r13d,r13d
 1ab45e2:	48 8b 84 24 c0 00 00 	mov    rax,QWORD PTR [rsp+0xc0]
 1ab45e9:	00
 1ab45ea:	48 8b 18             	mov    rbx,QWORD PTR [rax]
 1ab45ed:	4c 8b 23             	mov    r12,QWORD PTR [rbx]
 1ab45f0:	4d 85 e4             	test   r12,r12
 1ab45f3:	0f 84 af 03 00 00    	je     1ab49a8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3458>
 1ab45f9:	4c 89 ed             	mov    rbp,r13
 1ab45fc:	4c 8b 6b 08          	mov    r13,QWORD PTR [rbx+0x8]
 1ab4600:	bf 30 03 00 00       	mov    edi,0x330
 1ab4605:	ff 15 cd 99 cb 03    	call   QWORD PTR [rip+0x3cb99cd]        # 576dfd8 <__register_atfork@plt+0x10cd98>
 1ab460b:	48 85 c0             	test   rax,rax
 1ab460e:	0f 84 a1 03 00 00    	je     1ab49b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f344b>
 1ab4614:	49 89 c7             	mov    r15,rax
 1ab4617:	48 c7 80 c0 02 00 00 	mov    QWORD PTR [rax+0x2c0],0x0
 1ab461e:	00 00 00 00
 1ab4622:	66 c7 80 ca 02 00 00 	mov    WORD PTR [rax+0x2ca],0x0
 1ab4629:	00 00
 1ab462b:	4c 89 a0 d0 02 00 00 	mov    QWORD PTR [rax+0x2d0],r12
 1ab4632:	4c 89 e8             	mov    rax,r13
 1ab4635:	48 ff c0             	inc    rax
 1ab4638:	0f 84 89 03 00 00    	je     1ab49c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3439>
 1ab463e:	4d 89 bc 24 c0 02 00 	mov    QWORD PTR [r12+0x2c0],r15
 1ab4645:	00
 1ab4646:	66 41 c7 84 24 c8 02 	mov    WORD PTR [r12+0x2c8],0x0
 1ab464d:	00 00 00 00
 1ab4651:	4c 89 3b             	mov    QWORD PTR [rbx],r15
 1ab4654:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
 1ab4658:	4c 39 ed             	cmp    rbp,r13
 1ab465b:	0f 85 75 03 00 00    	jne    1ab49d6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f342a>
 1ab4661:	41 0f b7 87 ca 02 00 	movzx  eax,WORD PTR [r15+0x2ca]
 1ab4668:	00
 1ab4669:	48 83 f8 0b          	cmp    rax,0xb
 1ab466d:	0f 83 7c 03 00 00    	jae    1ab49ef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3411>
 1ab4673:	8d 48 01             	lea    ecx,[rax+0x1]
 1ab4676:	66 41 89 8f ca 02 00 	mov    WORD PTR [r15+0x2ca],cx
 1ab467d:	00
 1ab467e:	89 c2                	mov    edx,eax
 1ab4680:	c1 e2 05             	shl    edx,0x5
 1ab4683:	0f 28 44 24 50       	movaps xmm0,XMMWORD PTR [rsp+0x50]
 1ab4688:	0f 28 4c 24 60       	movaps xmm1,XMMWORD PTR [rsp+0x60]
 1ab468d:	41 0f 11 4c 17 10    	movups XMMWORD PTR [r15+rdx*1+0x10],xmm1
 1ab4693:	41 0f 11 04 17       	movups XMMWORD PTR [r15+rdx*1],xmm0
 1ab4698:	0f 28 44 24 70       	movaps xmm0,XMMWORD PTR [rsp+0x70]
 1ab469d:	0f 28 8c 24 80 00 00 	movaps xmm1,XMMWORD PTR [rsp+0x80]
 1ab46a4:	00
 1ab46a5:	41 0f 11 84 17 60 01 	movups XMMWORD PTR [r15+rdx*1+0x160],xmm0
 1ab46ac:	00 00
 1ab46ae:	41 0f 11 8c 17 70 01 	movups XMMWORD PTR [r15+rdx*1+0x170],xmm1
 1ab46b5:	00 00
 1ab46b7:	4d 89 b4 c7 d8 02 00 	mov    QWORD PTR [r15+rax*8+0x2d8],r14
 1ab46be:	00
 1ab46bf:	4d 89 be c0 02 00 00 	mov    QWORD PTR [r14+0x2c0],r15
 1ab46c6:	66 41 89 8e c8 02 00 	mov    WORD PTR [r14+0x2c8],cx
 1ab46cd:	00
 1ab46ce:	48 8b 7c 24 28       	mov    rdi,QWORD PTR [rsp+0x28]
 1ab46d3:	4c 8b 54 24 10       	mov    r10,QWORD PTR [rsp+0x10]
 1ab46d8:	48 8b 84 24 98 00 00 	mov    rax,QWORD PTR [rsp+0x98]
 1ab46df:	00
 1ab46e0:	4c 8b 7c 24 30       	mov    r15,QWORD PTR [rsp+0x30]
 1ab46e5:	4c 89 3f             	mov    QWORD PTR [rdi],r15
 1ab46e8:	48 89 47 08          	mov    QWORD PTR [rdi+0x8],rax
 1ab46ec:	4c 89 57 10          	mov    QWORD PTR [rdi+0x10],r10
 1ab46f0:	48 89 f8             	mov    rax,rdi
 1ab46f3:	48 81 c4 78 01 00 00 	add    rsp,0x178
 1ab46fa:	5b                   	pop    rbx
 1ab46fb:	41 5c                	pop    r12
 1ab46fd:	41 5d                	pop    r13
 1ab46ff:	41 5e                	pop    r14
 1ab4701:	41 5f                	pop    r15
 1ab4703:	5d                   	pop    rbp
 1ab4704:	c3                   	ret
