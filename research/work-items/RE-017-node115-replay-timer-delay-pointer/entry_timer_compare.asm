
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000057d44d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573f60>:
 57d44d0:	55                   	push   rbp
 57d44d1:	41 57                	push   r15
 57d44d3:	41 56                	push   r14
 57d44d5:	41 55                	push   r13
 57d44d7:	41 54                	push   r12
 57d44d9:	53                   	push   rbx
 57d44da:	48 81 ec b8 01 00 00 	sub    rsp,0x1b8
 57d44e1:	49 89 f7             	mov    r15,rsi
 57d44e4:	48 bd 08 ac 1c 5a 64 	movabs rbp,0xffdf3b645a1cac08
 57d44eb:	3b df ff
 57d44ee:	48 bb 11 58 39 b4 c8 	movabs rbx,0xffbe76c8b4395811
 57d44f5:	76 be ff
 57d44f8:	48 8b 06             	mov    rax,QWORD PTR [rsi]
 57d44fb:	48 89 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],rax
 57d4502:	00
 57d4503:	4c 8b 2f             	mov    r13,QWORD PTR [rdi]
 57d4506:	48 89 7c 24 78       	mov    QWORD PTR [rsp+0x78],rdi
 57d450b:	48 8b 47 18          	mov    rax,QWORD PTR [rdi+0x18]
 57d450f:	f2 0f 10 00          	movsd  xmm0,QWORD PTR [rax]
 57d4513:	8b 46 10             	mov    eax,DWORD PTR [rsi+0x10]
 57d4516:	89 84 24 d8 00 00 00 	mov    DWORD PTR [rsp+0xd8],eax
 57d451d:	48 8b 46 08          	mov    rax,QWORD PTR [rsi+0x8]
 57d4521:	48 89 84 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rax
 57d4528:	00
 57d4529:	ff 15 41 ca d0 00    	call   QWORD PTR [rip+0xd0ca41]        # 64e0f70 <__register_atfork@plt+0xef3e0>
 57d452f:	89 d6                	mov    esi,edx
 57d4531:	b9 00 ca 9a 3b       	mov    ecx,0x3b9aca00
 57d4536:	48 f7 e1             	mul    rcx
 57d4539:	48 89 c1             	mov    rcx,rax
 57d453c:	89 f0                	mov    eax,esi
 57d453e:	48 01 c1             	add    rcx,rax
 57d4541:	48 83 d2 00          	adc    rdx,0x0
 57d4545:	49 be ff ff ff ff ff 	movabs r14,0x7fffffffffffffff
 57d454c:	ff ff 7f
 57d454f:	4c 39 f1             	cmp    rcx,r14
 57d4552:	49 0f 43 ce          	cmovae rcx,r14
 57d4556:	48 85 d2             	test   rdx,rdx
 57d4559:	49 0f 45 ce          	cmovne rcx,r14
 57d455d:	48 ba b3 94 d6 26 e8 	movabs rdx,0x112e0be826d694b3
 57d4564:	0b 2e 11
 57d4567:	48 89 c8             	mov    rax,rcx
 57d456a:	48 f7 e2             	mul    rdx
 57d456d:	48 c1 ea 1a          	shr    rdx,0x1a
 57d4571:	69 c2 00 ca 9a 3b    	imul   eax,edx,0x3b9aca00
 57d4577:	29 c1                	sub    ecx,eax
 57d4579:	48 8d b4 24 d4 00 00 	lea    rsi,[rsp+0xd4]
 57d4580:	00
 57d4581:	4c 8d 64 24 10       	lea    r12,[rsp+0x10]
 57d4586:	4c 89 e7             	mov    rdi,r12
 57d4589:	ff 15 e9 c9 d0 00    	call   QWORD PTR [rip+0xd0c9e9]        # 64e0f78 <__register_atfork@plt+0xef3e8>
 57d458f:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
 57d4594:	48 8d 0c 28          	lea    rcx,[rax+rbp*1]
 57d4598:	48 39 d9             	cmp    rcx,rbx
 57d459b:	0f 82 8b 00 00 00    	jb     57d462c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573e04>
 57d45a1:	48 b9 00 00 00 00 40 	movabs rcx,0xffff574000000000
 57d45a8:	57 ff ff
 57d45ab:	48 01 c1             	add    rcx,rax
 57d45ae:	48 ba 81 ae fe ff 7f 	movabs rdx,0xfffeae7ffffeae81
 57d45b5:	ae fe ff
 57d45b8:	48 39 d1             	cmp    rcx,rdx
 57d45bb:	72 6f                	jb     57d462c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573e04>
 57d45bd:	8b 5c 24 10          	mov    ebx,DWORD PTR [rsp+0x10]
 57d45c1:	8b 4c 24 14          	mov    ecx,DWORD PTR [rsp+0x14]
 57d45c5:	89 4c 24 0c          	mov    DWORD PTR [rsp+0xc],ecx
 57d45c9:	8b bc 24 d0 00 00 00 	mov    edi,DWORD PTR [rsp+0xd0]
 57d45d0:	48 b9 57 29 51 ce a0 	movabs rcx,0x1845c8a0ce512957
 57d45d7:	c8 45 18
 57d45da:	48 f7 e9             	imul   rcx
 57d45dd:	48 89 d6             	mov    rsi,rdx
 57d45e0:	48 c1 ee 3f          	shr    rsi,0x3f
 57d45e4:	48 c1 ea 0d          	shr    rdx,0xd
 57d45e8:	01 d6                	add    esi,edx
 57d45ea:	ff 15 b0 c4 d0 00    	call   QWORD PTR [rip+0xd0c4b0]        # 64e0aa0 <__register_atfork@plt+0xeef10>
 57d45f0:	85 c0                	test   eax,eax
 57d45f2:	74 38                	je     57d462c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573e04>
 57d45f4:	89 44 24 10          	mov    DWORD PTR [rsp+0x10],eax
 57d45f8:	89 9c 24 30 01 00 00 	mov    DWORD PTR [rsp+0x130],ebx
 57d45ff:	8b 44 24 0c          	mov    eax,DWORD PTR [rsp+0xc]
 57d4603:	89 84 24 b0 00 00 00 	mov    DWORD PTR [rsp+0xb0],eax
 57d460a:	48 8d 84 24 b0 00 00 	lea    rax,[rsp+0xb0]
 57d4611:	00
 57d4612:	48 8d 8c 24 30 01 00 	lea    rcx,[rsp+0x130]
 57d4619:	00
 57d461a:	41 8b 14 24          	mov    edx,DWORD PTR [r12]
 57d461e:	41 39 55 00          	cmp    DWORD PTR [r13+0x0],edx
 57d4622:	0f 9d c2             	setge  dl
 57d4625:	74 33                	je     57d465a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573dd6>
 57d4627:	e9 50 01 00 00       	jmp    57d477c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573cb4>
 57d462c:	c7 44 24 10 00 00 00 	mov    DWORD PTR [rsp+0x10],0x0
 57d4633:	00
 57d4634:	4c 8d 25 95 33 c9 fa 	lea    r12,[rip+0xfffffffffac93395]        # 4679d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a60>
 57d463b:	48 8d 05 96 33 c9 fa 	lea    rax,[rip+0xfffffffffac93396]        # 4679d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a58>
 57d4642:	48 8d 0d 8b 33 c9 fa 	lea    rcx,[rip+0xfffffffffac9338b]        # 4679d4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a5c>
 57d4649:	41 8b 14 24          	mov    edx,DWORD PTR [r12]
 57d464d:	41 39 55 00          	cmp    DWORD PTR [r13+0x0],edx
 57d4651:	0f 9d c2             	setge  dl
 57d4654:	0f 85 22 01 00 00    	jne    57d477c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573cb4>
 57d465a:	8b 09                	mov    ecx,DWORD PTR [rcx]
 57d465c:	41 39 4d 04          	cmp    DWORD PTR [r13+0x4],ecx
 57d4660:	0f 93 c2             	setae  dl
 57d4663:	0f 85 13 01 00 00    	jne    57d477c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573cb4>
 57d4669:	8b 00                	mov    eax,DWORD PTR [rax]
 57d466b:	41 39 45 08          	cmp    DWORD PTR [r13+0x8],eax
 57d466f:	0f 82 0f 01 00 00    	jb     57d4784 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573cac>
 57d4675:	49 be 00 00 00 00 00 	movabs r14,0x8000000000000000
 57d467c:	00 00 80
 57d467f:	48 8b 5c 24 78       	mov    rbx,QWORD PTR [rsp+0x78]
 57d4684:	48 8b 73 08          	mov    rsi,QWORD PTR [rbx+0x8]
 57d4688:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 57d468d:	4c 8b bc 24 80 00 00 	mov    r15,QWORD PTR [rsp+0x80]
 57d4694:	00
 57d4695:	4c 89 fa             	mov    rdx,r15
 57d4698:	e8 53 37 ba ff       	call   5377df0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9d0640>
 57d469d:	49 8d 46 01          	lea    rax,[r14+0x1]
 57d46a1:	48 39 44 24 10       	cmp    QWORD PTR [rsp+0x10],rax
 57d46a6:	0f 84 9c 03 00 00    	je     57d4a48 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739e8>
 57d46ac:	0f 10 44 24 60       	movups xmm0,XMMWORD PTR [rsp+0x60]
 57d46b1:	0f 29 84 24 80 01 00 	movaps XMMWORD PTR [rsp+0x180],xmm0
 57d46b8:	00
 57d46b9:	0f 10 44 24 50       	movups xmm0,XMMWORD PTR [rsp+0x50]
 57d46be:	0f 29 84 24 70 01 00 	movaps XMMWORD PTR [rsp+0x170],xmm0
 57d46c5:	00
 57d46c6:	0f 10 44 24 10       	movups xmm0,XMMWORD PTR [rsp+0x10]
 57d46cb:	0f 10 4c 24 20       	movups xmm1,XMMWORD PTR [rsp+0x20]
 57d46d0:	0f 10 54 24 30       	movups xmm2,XMMWORD PTR [rsp+0x30]
 57d46d5:	0f 10 5c 24 40       	movups xmm3,XMMWORD PTR [rsp+0x40]
 57d46da:	0f 29 9c 24 60 01 00 	movaps XMMWORD PTR [rsp+0x160],xmm3
 57d46e1:	00
 57d46e2:	0f 29 94 24 50 01 00 	movaps XMMWORD PTR [rsp+0x150],xmm2
 57d46e9:	00
 57d46ea:	0f 29 8c 24 40 01 00 	movaps XMMWORD PTR [rsp+0x140],xmm1
 57d46f1:	00
 57d46f2:	0f 29 84 24 30 01 00 	movaps XMMWORD PTR [rsp+0x130],xmm0
 57d46f9:	00
 57d46fa:	0f 29 8c 24 a0 00 00 	movaps XMMWORD PTR [rsp+0xa0],xmm1
 57d4701:	00
 57d4702:	0f 29 84 24 90 00 00 	movaps XMMWORD PTR [rsp+0x90],xmm0
 57d4709:	00
 57d470a:	0f 29 9c 24 a0 01 00 	movaps XMMWORD PTR [rsp+0x1a0],xmm3
 57d4711:	00
 57d4712:	0f 29 94 24 90 01 00 	movaps XMMWORD PTR [rsp+0x190],xmm2
 57d4719:	00
 57d471a:	8b 05 b8 ba d1 00    	mov    eax,DWORD PTR [rip+0xd1bab8]        # 64f01d8 <__register_atfork@plt+0xfe648>
 57d4720:	85 c0                	test   eax,eax
 57d4722:	0f 85 34 03 00 00    	jne    57d4a5c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739d4>
 57d4728:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
 57d472c:	48 8b 48 58          	mov    rcx,QWORD PTR [rax+0x58]
 57d4730:	48 89 8c 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rcx
 57d4737:	00
 57d4738:	4c 8b 84 24 90 00 00 	mov    r8,QWORD PTR [rsp+0x90]
 57d473f:	00
 57d4740:	48 8b 8c 24 98 00 00 	mov    rcx,QWORD PTR [rsp+0x98]
 57d4747:	00
 57d4748:	48 8b 94 24 a0 00 00 	mov    rdx,QWORD PTR [rsp+0xa0]
 57d474f:	00
 57d4750:	48 8b b4 24 a8 00 00 	mov    rsi,QWORD PTR [rsp+0xa8]
 57d4757:	00
 57d4758:	4d 39 f0             	cmp    r8,r14
 57d475b:	0f 85 b0 01 00 00    	jne    57d4911 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b1f>
 57d4761:	31 ff                	xor    edi,edi
 57d4763:	48 85 c9             	test   rcx,rcx
 57d4766:	48 0f 44 f1          	cmove  rsi,rcx
 57d476a:	40 0f 95 c7          	setne  dil
 57d476e:	45 31 c0             	xor    r8d,r8d
 57d4771:	49 89 f1             	mov    r9,rsi
 57d4774:	48 89 fe             	mov    rsi,rdi
 57d4777:	e9 9a 01 00 00       	jmp    57d4916 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b1a>
 57d477c:	84 d2                	test   dl,dl
 57d477e:	0f 85 f1 fe ff ff    	jne    57d4675 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573dbb>
 57d4784:	49 83 c7 08          	add    r15,0x8
 57d4788:	41 8b 47 08          	mov    eax,DWORD PTR [r15+0x8]
 57d478c:	89 84 24 d8 00 00 00 	mov    DWORD PTR [rsp+0xd8],eax
 57d4793:	49 8b 07             	mov    rax,QWORD PTR [r15]
 57d4796:	48 89 84 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rax
 57d479d:	00
 57d479e:	f2 0f 10 05 72 4f c8 	movsd  xmm0,QWORD PTR [rip+0xfffffffffac84f72]        # 459718 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58eed18>
 57d47a5:	fa
 57d47a6:	ff 15 c4 c7 d0 00    	call   QWORD PTR [rip+0xd0c7c4]        # 64e0f70 <__register_atfork@plt+0xef3e0>
 57d47ac:	89 d6                	mov    esi,edx
 57d47ae:	b9 00 ca 9a 3b       	mov    ecx,0x3b9aca00
 57d47b3:	48 f7 e1             	mul    rcx
 57d47b6:	48 89 c1             	mov    rcx,rax
 57d47b9:	89 f0                	mov    eax,esi
 57d47bb:	48 01 c1             	add    rcx,rax
 57d47be:	48 83 d2 00          	adc    rdx,0x0
 57d47c2:	4c 39 f1             	cmp    rcx,r14
 57d47c5:	49 0f 43 ce          	cmovae rcx,r14
 57d47c9:	48 85 d2             	test   rdx,rdx
 57d47cc:	49 0f 45 ce          	cmovne rcx,r14
 57d47d0:	48 89 c8             	mov    rax,rcx
 57d47d3:	48 ba b3 94 d6 26 e8 	movabs rdx,0x112e0be826d694b3
 57d47da:	0b 2e 11
 57d47dd:	48 f7 e2             	mul    rdx
 57d47e0:	48 c1 ea 1a          	shr    rdx,0x1a
 57d47e4:	69 c2 00 ca 9a 3b    	imul   eax,edx,0x3b9aca00
 57d47ea:	29 c1                	sub    ecx,eax
 57d47ec:	48 8d b4 24 d4 00 00 	lea    rsi,[rsp+0xd4]
 57d47f3:	00
 57d47f4:	4c 8d 74 24 10       	lea    r14,[rsp+0x10]
 57d47f9:	4c 89 f7             	mov    rdi,r14
 57d47fc:	ff 15 76 c7 d0 00    	call   QWORD PTR [rip+0xd0c776]        # 64e0f78 <__register_atfork@plt+0xef3e8>
 57d4802:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
 57d4807:	48 01 c5             	add    rbp,rax
 57d480a:	48 b9 11 58 39 b4 c8 	movabs rcx,0xffbe76c8b4395811
 57d4811:	76 be ff
 57d4814:	48 39 cd             	cmp    rbp,rcx
 57d4817:	0f 82 81 00 00 00    	jb     57d489e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b92>
 57d481d:	48 b9 00 00 00 00 40 	movabs rcx,0xffff574000000000
 57d4824:	57 ff ff
 57d4827:	48 01 c1             	add    rcx,rax
 57d482a:	48 ba 81 ae fe ff 7f 	movabs rdx,0xfffeae7ffffeae81
 57d4831:	ae fe ff
 57d4834:	48 39 d1             	cmp    rcx,rdx
 57d4837:	72 65                	jb     57d489e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b92>
 57d4839:	8b 6c 24 10          	mov    ebp,DWORD PTR [rsp+0x10]
 57d483d:	44 8b 7c 24 14       	mov    r15d,DWORD PTR [rsp+0x14]
 57d4842:	8b bc 24 d0 00 00 00 	mov    edi,DWORD PTR [rsp+0xd0]
 57d4849:	48 b9 57 29 51 ce a0 	movabs rcx,0x1845c8a0ce512957
 57d4850:	c8 45 18
 57d4853:	48 f7 e9             	imul   rcx
 57d4856:	48 89 d6             	mov    rsi,rdx
 57d4859:	48 c1 ee 3f          	shr    rsi,0x3f
 57d485d:	48 c1 ea 0d          	shr    rdx,0xd
 57d4861:	01 d6                	add    esi,edx
 57d4863:	ff 15 37 c2 d0 00    	call   QWORD PTR [rip+0xd0c237]        # 64e0aa0 <__register_atfork@plt+0xeef10>
 57d4869:	85 c0                	test   eax,eax
 57d486b:	74 31                	je     57d489e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b92>
 57d486d:	89 44 24 10          	mov    DWORD PTR [rsp+0x10],eax
 57d4871:	89 ac 24 30 01 00 00 	mov    DWORD PTR [rsp+0x130],ebp
 57d4878:	44 89 bc 24 b0 00 00 	mov    DWORD PTR [rsp+0xb0],r15d
 57d487f:	00
 57d4880:	48 8d 84 24 b0 00 00 	lea    rax,[rsp+0xb0]
 57d4887:	00
 57d4888:	48 8d 8c 24 30 01 00 	lea    rcx,[rsp+0x130]
 57d488f:	00
 57d4890:	41 8b 16             	mov    edx,DWORD PTR [r14]
 57d4893:	41 39 55 00          	cmp    DWORD PTR [r13+0x0],edx
 57d4897:	0f 9d c2             	setge  dl
 57d489a:	74 2b                	je     57d48c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b69>
 57d489c:	eb 43                	jmp    57d48e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b4f>
 57d489e:	c7 44 24 10 00 00 00 	mov    DWORD PTR [rsp+0x10],0x0
 57d48a5:	00
 57d48a6:	4c 8d 35 23 31 c9 fa 	lea    r14,[rip+0xfffffffffac93123]        # 4679d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a60>
 57d48ad:	48 8d 05 24 31 c9 fa 	lea    rax,[rip+0xfffffffffac93124]        # 4679d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a58>
 57d48b4:	48 8d 0d 19 31 c9 fa 	lea    rcx,[rip+0xfffffffffac93119]        # 4679d4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e0a5c>
 57d48bb:	41 8b 16             	mov    edx,DWORD PTR [r14]
 57d48be:	41 39 55 00          	cmp    DWORD PTR [r13+0x0],edx
 57d48c2:	0f 9d c2             	setge  dl
 57d48c5:	75 1a                	jne    57d48e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b4f>
 57d48c7:	8b 09                	mov    ecx,DWORD PTR [rcx]
 57d48c9:	41 39 4d 04          	cmp    DWORD PTR [r13+0x4],ecx
 57d48cd:	0f 93 c2             	setae  dl
 57d48d0:	75 0f                	jne    57d48e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b4f>
 57d48d2:	8b 08                	mov    ecx,DWORD PTR [rax]
 57d48d4:	b0 01                	mov    al,0x1
 57d48d6:	41 39 4d 08          	cmp    DWORD PTR [r13+0x8],ecx
 57d48da:	73 0f                	jae    57d48eb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573b45>
 57d48dc:	e9 69 01 00 00       	jmp    57d4a4a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739e6>
 57d48e1:	b0 01                	mov    al,0x1
 57d48e3:	84 d2                	test   dl,dl
 57d48e5:	0f 84 5f 01 00 00    	je     57d4a4a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739e6>
 57d48eb:	48 8b 44 24 78       	mov    rax,QWORD PTR [rsp+0x78]
 57d48f0:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
 57d48f4:	48 8b 70 30          	mov    rsi,QWORD PTR [rax+0x30]
 57d48f8:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
 57d48fb:	b0 01                	mov    al,0x1
 57d48fd:	48 3b 16             	cmp    rdx,QWORD PTR [rsi]
 57d4900:	0f 83 44 01 00 00    	jae    57d4a4a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739e6>
 57d4906:	48 ff c2             	inc    rdx
 57d4909:	48 89 11             	mov    QWORD PTR [rcx],rdx
 57d490c:	e9 37 01 00 00       	jmp    57d4a48 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5739e8>
 57d4911:	bf 02 00 00 00       	mov    edi,0x2
 57d4916:	48 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],rdi
 57d491b:	4c 89 44 24 18       	mov    QWORD PTR [rsp+0x18],r8
 57d4920:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
 57d4925:	48 89 54 24 28       	mov    QWORD PTR [rsp+0x28],rdx
 57d492a:	48 89 74 24 30       	mov    QWORD PTR [rsp+0x30],rsi
 57d492f:	48 c7 44 24 38 00 00 	mov    QWORD PTR [rsp+0x38],0x0
 57d4936:	00 00
 57d4938:	48 89 4c 24 40       	mov    QWORD PTR [rsp+0x40],rcx
 57d493d:	48 89 54 24 48       	mov    QWORD PTR [rsp+0x48],rdx
 57d4942:	4c 89 4c 24 50       	mov    QWORD PTR [rsp+0x50],r9
 57d4947:	48 89 44 24 58       	mov    QWORD PTR [rsp+0x58],rax
 57d494c:	48 8d 84 24 88 00 00 	lea    rax,[rsp+0x88]
 57d4953:	00
 57d4954:	48 89 44 24 60       	mov    QWORD PTR [rsp+0x60],rax
 57d4959:	31 ed                	xor    ebp,ebp
 57d495b:	48 8d bc 24 d0 00 00 	lea    rdi,[rsp+0xd0]
 57d4962:	00
 57d4963:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
 57d4968:	e8 c3 5e 3a 00       	call   5b7a830 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1cdc00>
 57d496d:	31 ed                	xor    ebp,ebp
 57d496f:	48 8d bc 24 b0 00 00 	lea    rdi,[rsp+0xb0]
 57d4976:	00
 57d4977:	48 8d b4 24 d0 00 00 	lea    rsi,[rsp+0xd0]
 57d497e:	00
 57d497f:	e8 ac b9 5e ff       	call   4dc0330 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf88100>
 57d4984:	48 8d 84 24 70 01 00 	lea    rax,[rsp+0x170]
 57d498b:	00
 57d498c:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
 57d4990:	0f 10 00             	movups xmm0,XMMWORD PTR [rax]
 57d4993:	0f 10 48 10          	movups xmm1,XMMWORD PTR [rax+0x10]
 57d4997:	0f 29 8c 24 20 01 00 	movaps XMMWORD PTR [rsp+0x120],xmm1
 57d499e:	00
 57d499f:	0f 29 84 24 10 01 00 	movaps XMMWORD PTR [rsp+0x110],xmm0
 57d49a6:	00
 57d49a7:	0f 10 50 e0          	movups xmm2,XMMWORD PTR [rax-0x20]
 57d49ab:	0f 10 58 f0          	movups xmm3,XMMWORD PTR [rax-0x10]
 57d49af:	0f 10 a4 24 b0 00 00 	movups xmm4,XMMWORD PTR [rsp+0xb0]
 57d49b6:	00
 57d49b7:	0f 10 ac 24 c0 00 00 	movups xmm5,XMMWORD PTR [rsp+0xc0]
 57d49be:	00
 57d49bf:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 57d49c4:	0f 11 64 24 18       	movups XMMWORD PTR [rsp+0x18],xmm4
 57d49c9:	0f 11 6c 24 28       	movups XMMWORD PTR [rsp+0x28],xmm5
 57d49ce:	0f 11 54 24 38       	movups XMMWORD PTR [rsp+0x38],xmm2
 57d49d3:	0f 11 5c 24 48       	movups XMMWORD PTR [rsp+0x48],xmm3
 57d49d8:	0f 11 44 24 58       	movups XMMWORD PTR [rsp+0x58],xmm0
 57d49dd:	0f 11 4c 24 68       	movups XMMWORD PTR [rsp+0x68],xmm1
 57d49e2:	4c 8b 73 10          	mov    r14,QWORD PTR [rbx+0x10]
 57d49e6:	4c 3b 33             	cmp    r14,QWORD PTR [rbx]
 57d49e9:	75 09                	jne    57d49f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573a3c>
 57d49eb:	48 89 df             	mov    rdi,rbx
 57d49ee:	ff 15 1c 07 d1 00    	call   QWORD PTR [rip+0xd1071c]        # 64e5110 <__register_atfork@plt+0xf3580>
 57d49f4:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
 57d49f8:	49 6b ce 68          	imul   rcx,r14,0x68
 57d49fc:	48 8b 54 24 70       	mov    rdx,QWORD PTR [rsp+0x70]
 57d4a01:	48 89 54 08 60       	mov    QWORD PTR [rax+rcx*1+0x60],rdx
 57d4a06:	0f 10 44 24 60       	movups xmm0,XMMWORD PTR [rsp+0x60]
 57d4a0b:	0f 11 44 08 50       	movups XMMWORD PTR [rax+rcx*1+0x50],xmm0
 57d4a10:	0f 10 44 24 50       	movups xmm0,XMMWORD PTR [rsp+0x50]
 57d4a15:	0f 11 44 08 40       	movups XMMWORD PTR [rax+rcx*1+0x40],xmm0
 57d4a1a:	0f 10 44 24 10       	movups xmm0,XMMWORD PTR [rsp+0x10]
 57d4a1f:	0f 10 4c 24 20       	movups xmm1,XMMWORD PTR [rsp+0x20]
 57d4a24:	0f 10 54 24 30       	movups xmm2,XMMWORD PTR [rsp+0x30]
 57d4a29:	0f 10 5c 24 40       	movups xmm3,XMMWORD PTR [rsp+0x40]
 57d4a2e:	0f 11 5c 08 30       	movups XMMWORD PTR [rax+rcx*1+0x30],xmm3
 57d4a33:	0f 11 54 08 20       	movups XMMWORD PTR [rax+rcx*1+0x20],xmm2
 57d4a38:	0f 11 4c 08 10       	movups XMMWORD PTR [rax+rcx*1+0x10],xmm1
 57d4a3d:	0f 11 04 08          	movups XMMWORD PTR [rax+rcx*1],xmm0
 57d4a41:	49 ff c6             	inc    r14
 57d4a44:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
 57d4a48:	31 c0                	xor    eax,eax
 57d4a4a:	48 81 c4 b8 01 00 00 	add    rsp,0x1b8
 57d4a51:	5b                   	pop    rbx
 57d4a52:	41 5c                	pop    r12
 57d4a54:	41 5d                	pop    r13
 57d4a56:	41 5e                	pop    r14
 57d4a58:	41 5f                	pop    r15
 57d4a5a:	5d                   	pop    rbp
 57d4a5b:	c3                   	ret
 57d4a5c:	48 8d 05 5d b7 d1 00 	lea    rax,[rip+0xd1b75d]        # 64f01c0 <__register_atfork@plt+0xfe630>
 57d4a63:	48 89 84 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rax
 57d4a6a:	00
 57d4a6b:	48 8d 84 24 d0 00 00 	lea    rax,[rsp+0xd0]
 57d4a72:	00
 57d4a73:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 57d4a78:	40 b5 01             	mov    bpl,0x1
 57d4a7b:	48 8d 3d 56 b7 d1 00 	lea    rdi,[rip+0xd1b756]        # 64f01d8 <__register_atfork@plt+0xfe648>
 57d4a82:	48 8d 0d c7 97 c2 00 	lea    rcx,[rip+0xc297c7]        # 63fe250 <__register_atfork@plt+0xc6c0>
 57d4a89:	4c 8d 05 e8 97 c2 00 	lea    r8,[rip+0xc297e8]        # 63fe278 <__register_atfork@plt+0xc6e8>
 57d4a90:	48 8d 54 24 10       	lea    rdx,[rsp+0x10]
 57d4a95:	be 01 00 00 00       	mov    esi,0x1
 57d4a9a:	ff 15 50 af d0 00    	call   QWORD PTR [rip+0xd0af50]        # 64df9f0 <__register_atfork@plt+0xede60>
 57d4aa0:	e9 83 fc ff ff       	jmp    57d4728 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573d08>
 57d4aa5:	48 89 c3             	mov    rbx,rax
 57d4aa8:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 57d4aad:	e8 be 44 00 00       	call   57d8f70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x56f4c0>
 57d4ab2:	eb 28                	jmp    57d4adc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573954>
 57d4ab4:	ff 15 06 aa d0 00    	call   QWORD PTR [rip+0xd0aa06]        # 64df4c0 <__register_atfork@plt+0xed930>
 57d4aba:	48 89 c3             	mov    rbx,rax
 57d4abd:	48 8d bc 24 90 01 00 	lea    rdi,[rsp+0x190]
 57d4ac4:	00
 57d4ac5:	e8 06 3c 00 00       	call   57d86d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x56fd60>
 57d4aca:	40 84 ed             	test   bpl,bpl
 57d4acd:	74 0d                	je     57d4adc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573954>
 57d4acf:	48 8d bc 24 90 00 00 	lea    rdi,[rsp+0x90]
 57d4ad6:	00
 57d4ad7:	e8 b4 36 00 00       	call   57d8190 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5702a0>
 57d4adc:	48 89 df             	mov    rdi,rbx
 57d4adf:	e8 6c bf c1 00       	call   63f0a50 <_Unwind_Resume@plt>
 57d4ae4:	ff 15 d6 a9 d0 00    	call   QWORD PTR [rip+0xd0a9d6]        # 64df4c0 <__register_atfork@plt+0xed930>
