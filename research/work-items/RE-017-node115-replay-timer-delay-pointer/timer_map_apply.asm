
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004de0540 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67ef0>:
 4de0540:	41 57                	push   r15
 4de0542:	41 56                	push   r14
 4de0544:	41 55                	push   r13
 4de0546:	41 54                	push   r12
 4de0548:	53                   	push   rbx
 4de0549:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
 4de0550:	48 89 fb             	mov    rbx,rdi
 4de0553:	49 bd 00 00 00 00 00 	movabs r13,0x8000000000000000
 4de055a:	00 00 80
 4de055d:	31 c0                	xor    eax,eax
 4de055f:	48 3b 07             	cmp    rax,QWORD PTR [rdi]
 4de0562:	0f 81 8f 00 00 00    	jno    4de05f7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67e39>
 4de0568:	4c 8d 63 08          	lea    r12,[rbx+0x8]
 4de056c:	48 8b 46 30          	mov    rax,QWORD PTR [rsi+0x30]
 4de0570:	48 89 84 24 a0 00 00 	mov    QWORD PTR [rsp+0xa0],rax
 4de0577:	00
 4de0578:	0f 10 06             	movups xmm0,XMMWORD PTR [rsi]
 4de057b:	0f 10 4e 10          	movups xmm1,XMMWORD PTR [rsi+0x10]
 4de057f:	0f 10 56 20          	movups xmm2,XMMWORD PTR [rsi+0x20]
 4de0583:	0f 29 94 24 90 00 00 	movaps XMMWORD PTR [rsp+0x90],xmm2
 4de058a:	00
 4de058b:	0f 29 8c 24 80 00 00 	movaps XMMWORD PTR [rsp+0x80],xmm1
 4de0592:	00
 4de0593:	0f 29 44 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm0
 4de0598:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
 4de059c:	48 85 c0             	test   rax,rax
 4de059f:	0f 84 c0 00 00 00    	je     4de0665 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67dcb>
 4de05a5:	48 8b 4b 10          	mov    rcx,QWORD PTR [rbx+0x10]
 4de05a9:	48 85 c9             	test   rcx,rcx
 4de05ac:	0f 84 9c 01 00 00    	je     4de074e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67ce2>
 4de05b2:	48 89 ca             	mov    rdx,rcx
 4de05b5:	48 83 e2 07          	and    rdx,0x7
 4de05b9:	0f 84 3c 01 00 00    	je     4de06fb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67d35>
 4de05bf:	31 f6                	xor    esi,esi
 4de05c1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 4de05c8:	0f 1f 84 00 00 00 00
 4de05cf:	00
 4de05d0:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de05d7:	48 ff c6             	inc    rsi
 4de05da:	48 39 f2             	cmp    rdx,rsi
 4de05dd:	75 f1                	jne    4de05d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67e60>
 4de05df:	48 89 ca             	mov    rdx,rcx
 4de05e2:	48 29 f2             	sub    rdx,rsi
 4de05e5:	4c 89 e6             	mov    rsi,r12
 4de05e8:	48 83 f9 08          	cmp    rcx,0x8
 4de05ec:	0f 83 1e 01 00 00    	jae    4de0710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67d20>
 4de05f2:	e9 5a 01 00 00       	jmp    4de0751 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67cdf>
 4de05f7:	48 89 df             	mov    rdi,rbx
 4de05fa:	e8 91 10 a1 00       	call   57f1690 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556da0>
 4de05ff:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
 4de0603:	4c 39 2b             	cmp    QWORD PTR [rbx],r13
 4de0606:	0f 94 c1             	sete   cl
 4de0609:	48 83 f8 20          	cmp    rax,0x20
 4de060d:	0f 92 c2             	setb   dl
 4de0610:	20 ca                	and    dl,cl
 4de0612:	80 fa 01             	cmp    dl,0x1
 4de0615:	0f 85 bc 02 00 00    	jne    4de08d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67b59>
 4de061b:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
 4de061f:	48 8b 53 10          	mov    rdx,QWORD PTR [rbx+0x10]
 4de0623:	48 c7 43 08 00 00 00 	mov    QWORD PTR [rbx+0x8],0x0
 4de062a:	00
 4de062b:	48 c7 43 18 00 00 00 	mov    QWORD PTR [rbx+0x18],0x0
 4de0632:	00
 4de0633:	48 85 c9             	test   rcx,rcx
 4de0636:	74 36                	je     4de066e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67dc2>
 4de0638:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
 4de063f:	00 00
 4de0641:	48 89 4c 24 38       	mov    QWORD PTR [rsp+0x38],rcx
 4de0646:	48 89 54 24 40       	mov    QWORD PTR [rsp+0x40],rdx
 4de064b:	48 c7 44 24 50 00 00 	mov    QWORD PTR [rsp+0x50],0x0
 4de0652:	00 00
 4de0654:	48 89 4c 24 58       	mov    QWORD PTR [rsp+0x58],rcx
 4de0659:	48 89 54 24 60       	mov    QWORD PTR [rsp+0x60],rdx
 4de065e:	b9 01 00 00 00       	mov    ecx,0x1
 4de0663:	eb 0d                	jmp    4de0672 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67dbe>
 4de0665:	31 c0                	xor    eax,eax
 4de0667:	31 f6                	xor    esi,esi
 4de0669:	e9 e3 00 00 00       	jmp    4de0751 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67cdf>
 4de066e:	31 c9                	xor    ecx,ecx
 4de0670:	31 c0                	xor    eax,eax
 4de0672:	48 89 4c 24 28       	mov    QWORD PTR [rsp+0x28],rcx
 4de0677:	48 89 4c 24 48       	mov    QWORD PTR [rsp+0x48],rcx
 4de067c:	48 89 44 24 68       	mov    QWORD PTR [rsp+0x68],rax
 4de0681:	4c 8d 74 24 70       	lea    r14,[rsp+0x70]
 4de0686:	48 8d 74 24 28       	lea    rsi,[rsp+0x28]
 4de068b:	4c 89 f7             	mov    rdi,r14
 4de068e:	e8 cd 61 da 00       	call   5b86860 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1c1bd0>
 4de0693:	0f 10 44 24 70       	movups xmm0,XMMWORD PTR [rsp+0x70]
 4de0698:	48 8b 84 24 80 00 00 	mov    rax,QWORD PTR [rsp+0x80]
 4de069f:	00
 4de06a0:	48 c7 44 24 18 00 00 	mov    QWORD PTR [rsp+0x18],0x0
 4de06a7:	00 00
 4de06a9:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 4de06ae:	0f 11 44 24 08       	movups XMMWORD PTR [rsp+0x8],xmm0
 4de06b3:	48 c7 44 24 70 00 00 	mov    QWORD PTR [rsp+0x70],0x0
 4de06ba:	00 00
 4de06bc:	48 c7 84 24 90 00 00 	mov    QWORD PTR [rsp+0x90],0x0
 4de06c3:	00 00 00 00 00
 4de06c8:	48 c7 84 24 b0 00 00 	mov    QWORD PTR [rsp+0xb0],0x0
 4de06cf:	00 00 00 00 00
 4de06d4:	4c 8d bc 24 b8 00 00 	lea    r15,[rsp+0xb8]
 4de06db:	00
 4de06dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 4de06e0:	4c 89 ff             	mov    rdi,r15
 4de06e3:	4c 89 f6             	mov    rsi,r14
 4de06e6:	e8 85 bd 3f 00       	call   51dc470 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb6bfc0>
 4de06eb:	48 83 bc 24 b8 00 00 	cmp    QWORD PTR [rsp+0xb8],0x0
 4de06f2:	00 00
 4de06f4:	75 ea                	jne    4de06e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67d50>
 4de06f6:	e9 cb 01 00 00       	jmp    4de08c6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67b6a>
 4de06fb:	48 89 ca             	mov    rdx,rcx
 4de06fe:	4c 89 e6             	mov    rsi,r12
 4de0701:	48 83 f9 08          	cmp    rcx,0x8
 4de0705:	72 4a                	jb     4de0751 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67cdf>
 4de0707:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
 4de070e:	00 00
 4de0710:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de0717:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de071e:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de0725:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de072c:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de0733:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de073a:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de0741:	48 8b 80 e8 00 00 00 	mov    rax,QWORD PTR [rax+0xe8]
 4de0748:	48 83 c2 f8          	add    rdx,0xfffffffffffffff8
 4de074c:	75 c2                	jne    4de0710 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67d20>
 4de074e:	4c 89 e6             	mov    rsi,r12
 4de0751:	48 8d 4b 18          	lea    rcx,[rbx+0x18]
 4de0755:	48 8d 54 24 70       	lea    rdx,[rsp+0x70]
 4de075a:	48 89 54 24 28       	mov    QWORD PTR [rsp+0x28],rdx
 4de075f:	48 89 4c 24 30       	mov    QWORD PTR [rsp+0x30],rcx
 4de0764:	48 89 74 24 38       	mov    QWORD PTR [rsp+0x38],rsi
 4de0769:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
 4de076e:	0f 57 c0             	xorps  xmm0,xmm0
 4de0771:	0f 11 44 24 48       	movups XMMWORD PTR [rsp+0x48],xmm0
 4de0776:	4c 8d 74 24 08       	lea    r14,[rsp+0x8]
 4de077b:	4c 8d 7c 24 28       	lea    r15,[rsp+0x28]
 4de0780:	4c 89 f7             	mov    rdi,r14
 4de0783:	4c 89 fe             	mov    rsi,r15
 4de0786:	e8 65 19 37 00       	call   51520f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xbf6340>
 4de078b:	83 7c 24 10 00       	cmp    DWORD PTR [rsp+0x10],0x0
 4de0790:	75 ee                	jne    4de0780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67cb0>
 4de0792:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
 4de0796:	4c 39 2b             	cmp    QWORD PTR [rbx],r13
 4de0799:	0f 94 c1             	sete   cl
 4de079c:	48 83 f8 20          	cmp    rax,0x20
 4de07a0:	0f 92 c2             	setb   dl
 4de07a3:	20 ca                	and    dl,cl
 4de07a5:	80 fa 01             	cmp    dl,0x1
 4de07a8:	0f 85 29 01 00 00    	jne    4de08d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67b59>
 4de07ae:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
 4de07b2:	48 8b 53 10          	mov    rdx,QWORD PTR [rbx+0x10]
 4de07b6:	48 c7 43 08 00 00 00 	mov    QWORD PTR [rbx+0x8],0x0
 4de07bd:	00
 4de07be:	48 c7 43 18 00 00 00 	mov    QWORD PTR [rbx+0x18],0x0
 4de07c5:	00
 4de07c6:	48 85 c9             	test   rcx,rcx
 4de07c9:	74 2d                	je     4de07f8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67c38>
 4de07cb:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
 4de07d2:	00 00
 4de07d4:	48 89 4c 24 38       	mov    QWORD PTR [rsp+0x38],rcx
 4de07d9:	48 89 54 24 40       	mov    QWORD PTR [rsp+0x40],rdx
 4de07de:	48 c7 44 24 50 00 00 	mov    QWORD PTR [rsp+0x50],0x0
 4de07e5:	00 00
 4de07e7:	48 89 4c 24 58       	mov    QWORD PTR [rsp+0x58],rcx
 4de07ec:	48 89 54 24 60       	mov    QWORD PTR [rsp+0x60],rdx
 4de07f1:	b9 01 00 00 00       	mov    ecx,0x1
 4de07f6:	eb 04                	jmp    4de07fc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67c34>
 4de07f8:	31 c9                	xor    ecx,ecx
 4de07fa:	31 c0                	xor    eax,eax
 4de07fc:	48 89 4c 24 28       	mov    QWORD PTR [rsp+0x28],rcx
 4de0801:	48 89 4c 24 48       	mov    QWORD PTR [rsp+0x48],rcx
 4de0806:	48 89 44 24 68       	mov    QWORD PTR [rsp+0x68],rax
 4de080b:	48 8d 7c 24 70       	lea    rdi,[rsp+0x70]
 4de0810:	48 8d 74 24 28       	lea    rsi,[rsp+0x28]
 4de0815:	e8 46 60 da 00       	call   5b86860 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1c1bd0>
 4de081a:	0f 10 44 24 70       	movups xmm0,XMMWORD PTR [rsp+0x70]
 4de081f:	48 8b 84 24 80 00 00 	mov    rax,QWORD PTR [rsp+0x80]
 4de0826:	00
 4de0827:	48 c7 44 24 18 00 00 	mov    QWORD PTR [rsp+0x18],0x0
 4de082e:	00 00
 4de0830:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 4de0835:	0f 11 44 24 08       	movups XMMWORD PTR [rsp+0x8],xmm0
 4de083a:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
 4de083e:	48 85 c9             	test   rcx,rcx
 4de0841:	74 44                	je     4de0887 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67ba9>
 4de0843:	48 8b 53 10          	mov    rdx,QWORD PTR [rbx+0x10]
 4de0847:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
 4de084b:	48 c7 44 24 78 00 00 	mov    QWORD PTR [rsp+0x78],0x0
 4de0852:	00 00
 4de0854:	48 89 8c 24 80 00 00 	mov    QWORD PTR [rsp+0x80],rcx
 4de085b:	00
 4de085c:	48 89 94 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rdx
 4de0863:	00
 4de0864:	48 c7 84 24 98 00 00 	mov    QWORD PTR [rsp+0x98],0x0
 4de086b:	00 00 00 00 00
 4de0870:	48 89 8c 24 a0 00 00 	mov    QWORD PTR [rsp+0xa0],rcx
 4de0877:	00
 4de0878:	48 89 94 24 a8 00 00 	mov    QWORD PTR [rsp+0xa8],rdx
 4de087f:	00
 4de0880:	b9 01 00 00 00       	mov    ecx,0x1
 4de0885:	eb 04                	jmp    4de088b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67ba5>
 4de0887:	31 c9                	xor    ecx,ecx
 4de0889:	31 c0                	xor    eax,eax
 4de088b:	48 89 4c 24 70       	mov    QWORD PTR [rsp+0x70],rcx
 4de0890:	48 89 8c 24 90 00 00 	mov    QWORD PTR [rsp+0x90],rcx
 4de0897:	00
 4de0898:	48 89 84 24 b0 00 00 	mov    QWORD PTR [rsp+0xb0],rax
 4de089f:	00
 4de08a0:	4c 8d bc 24 b8 00 00 	lea    r15,[rsp+0xb8]
 4de08a7:	00
 4de08a8:	4c 8d 64 24 70       	lea    r12,[rsp+0x70]
 4de08ad:	0f 1f 00             	nop    DWORD PTR [rax]
 4de08b0:	4c 89 ff             	mov    rdi,r15
 4de08b3:	4c 89 e6             	mov    rsi,r12
 4de08b6:	e8 b5 bb 3f 00       	call   51dc470 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb6bfc0>
 4de08bb:	48 83 bc 24 b8 00 00 	cmp    QWORD PTR [rsp+0xb8],0x0
 4de08c2:	00 00
 4de08c4:	75 ea                	jne    4de08b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67b80>
 4de08c6:	0f 10 44 24 08       	movups xmm0,XMMWORD PTR [rsp+0x8]
 4de08cb:	0f 10 4c 24 18       	movups xmm1,XMMWORD PTR [rsp+0x18]
 4de08d0:	0f 11 4b 10          	movups XMMWORD PTR [rbx+0x10],xmm1
 4de08d4:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
 4de08d7:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
 4de08de:	5b                   	pop    rbx
 4de08df:	41 5c                	pop    r12
 4de08e1:	41 5d                	pop    r13
 4de08e3:	41 5e                	pop    r14
 4de08e5:	41 5f                	pop    r15
 4de08e7:	c3                   	ret
 4de08e8:	eb 05                	jmp    4de08ef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67b41>
 4de08ea:	4c 8d 74 24 08       	lea    r14,[rsp+0x8]
 4de08ef:	41 0f 10 06          	movups xmm0,XMMWORD PTR [r14]
 4de08f3:	41 0f 10 4e 10       	movups xmm1,XMMWORD PTR [r14+0x10]
 4de08f8:	0f 11 4b 10          	movups XMMWORD PTR [rbx+0x10],xmm1
 4de08fc:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
 4de08ff:	48 89 c7             	mov    rdi,rax
 4de0902:	e8 49 01 61 01       	call   63f0a50 <_Unwind_Resume@plt>
