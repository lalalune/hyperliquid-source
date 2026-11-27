
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000057f1690 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556da0>:
 57f1690:	55                   	push   rbp
 57f1691:	41 57                	push   r15
 57f1693:	41 56                	push   r14
 57f1695:	41 55                	push   r13
 57f1697:	41 54                	push   r12
 57f1699:	53                   	push   rbx
 57f169a:	48 83 ec 38          	sub    rsp,0x38
 57f169e:	48 89 74 24 10       	mov    QWORD PTR [rsp+0x10],rsi
 57f16a3:	49 89 fe             	mov    r14,rdi
 57f16a6:	4c 8b 67 18          	mov    r12,QWORD PTR [rdi+0x18]
 57f16aa:	4d 85 e4             	test   r12,r12
 57f16ad:	74 5e                	je     57f170d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556d23>
 57f16af:	49 8b 5e 10          	mov    rbx,QWORD PTR [r14+0x10]
 57f16b3:	4d 8b 3e             	mov    r15,QWORD PTR [r14]
 57f16b6:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
 57f16ba:	48 8d 0c 5b          	lea    rcx,[rbx+rbx*2]
 57f16be:	48 8d 2c c8          	lea    rbp,[rax+rcx*8]
 57f16c2:	48 83 c5 e8          	add    rbp,0xffffffffffffffe8
 57f16c6:	45 31 ed             	xor    r13d,r13d
 57f16c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 57f16d0:	4a 8d 04 2b          	lea    rax,[rbx+r13*1]
 57f16d4:	4c 39 f8             	cmp    rax,r15
 57f16d7:	b8 00 00 00 00       	mov    eax,0x0
 57f16dc:	49 0f 43 c7          	cmovae rax,r15
 57f16e0:	48 c1 e0 03          	shl    rax,0x3
 57f16e4:	48 8d 04 40          	lea    rax,[rax+rax*2]
 57f16e8:	48 83 c5 18          	add    rbp,0x18
 57f16ec:	48 89 ee             	mov    rsi,rbp
 57f16ef:	48 29 c6             	sub    rsi,rax
 57f16f2:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
 57f16f7:	e8 d4 2d fe ff       	call   57d44d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573f60>
 57f16fc:	84 c0                	test   al,al
 57f16fe:	74 1c                	je     57f171c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556d14>
 57f1700:	49 ff c5             	inc    r13
 57f1703:	4d 39 ec             	cmp    r12,r13
 57f1706:	75 c8                	jne    57f16d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556d60>
 57f1708:	e9 3f 01 00 00       	jmp    57f184c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556be4>
 57f170d:	45 31 ed             	xor    r13d,r13d
 57f1710:	31 c0                	xor    eax,eax
 57f1712:	4c 39 e0             	cmp    rax,r12
 57f1715:	72 12                	jb     57f1729 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556d07>
 57f1717:	e9 22 01 00 00       	jmp    57f183e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556bf2>
 57f171c:	49 8d 45 01          	lea    rax,[r13+0x1]
 57f1720:	4c 39 e0             	cmp    rax,r12
 57f1723:	0f 83 15 01 00 00    	jae    57f183e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556bf2>
 57f1729:	49 8b 56 10          	mov    rdx,QWORD PTR [r14+0x10]
 57f172d:	49 8b 1e             	mov    rbx,QWORD PTR [r14]
 57f1730:	4c 89 74 24 08       	mov    QWORD PTR [rsp+0x8],r14
 57f1735:	49 8b 7e 08          	mov    rdi,QWORD PTR [r14+0x8]
 57f1739:	4c 89 24 24          	mov    QWORD PTR [rsp],r12
 57f173d:	48 89 7c 24 18       	mov    QWORD PTR [rsp+0x18],rdi
 57f1742:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
 57f1746:	48 8d 0c 49          	lea    rcx,[rcx+rcx*2]
 57f174a:	4c 8d 34 cf          	lea    r14,[rdi+rcx*8]
 57f174e:	48 89 c5             	mov    rbp,rax
 57f1751:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 57f1758:	0f 1f 84 00 00 00 00
 57f175f:	00
 57f1760:	49 89 d4             	mov    r12,rdx
 57f1763:	48 8d 04 2a          	lea    rax,[rdx+rbp*1]
 57f1767:	48 39 d8             	cmp    rax,rbx
 57f176a:	48 89 d8             	mov    rax,rbx
 57f176d:	b9 00 00 00 00       	mov    ecx,0x0
 57f1772:	48 0f 42 c1          	cmovb  rax,rcx
 57f1776:	48 c1 e0 03          	shl    rax,0x3
 57f177a:	48 8d 04 40          	lea    rax,[rax+rax*2]
 57f177e:	4d 89 f7             	mov    r15,r14
 57f1781:	49 29 c7             	sub    r15,rax
 57f1784:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
 57f1789:	4c 89 fe             	mov    rsi,r15
 57f178c:	e8 3f 2d fe ff       	call   57d44d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x573f60>
 57f1791:	84 c0                	test   al,al
 57f1793:	75 1b                	jne    57f17b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556c80>
 57f1795:	48 ff c5             	inc    rbp
 57f1798:	49 83 c6 18          	add    r14,0x18
 57f179c:	48 3b 2c 24          	cmp    rbp,QWORD PTR [rsp]
 57f17a0:	4c 89 e2             	mov    rdx,r12
 57f17a3:	72 bb                	jb     57f1760 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556cd0>
 57f17a5:	e9 88 00 00 00       	jmp    57f1832 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556bfe>
 57f17aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
 57f17b0:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
 57f17b4:	49 39 f5             	cmp    r13,rsi
 57f17b7:	0f 83 9e 00 00 00    	jae    57f185b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556bd5>
 57f17bd:	4c 89 e2             	mov    rdx,r12
 57f17c0:	4b 8d 04 2c          	lea    rax,[r12+r13*1]
 57f17c4:	48 39 d8             	cmp    rax,rbx
 57f17c7:	b9 00 00 00 00       	mov    ecx,0x0
 57f17cc:	48 0f 43 cb          	cmovae rcx,rbx
 57f17d0:	48 29 c8             	sub    rax,rcx
 57f17d3:	48 8d 04 40          	lea    rax,[rax+rax*2]
 57f17d7:	48 8b 7c 24 18       	mov    rdi,QWORD PTR [rsp+0x18]
 57f17dc:	48 8b 4c c7 10       	mov    rcx,QWORD PTR [rdi+rax*8+0x10]
 57f17e1:	48 89 4c 24 30       	mov    QWORD PTR [rsp+0x30],rcx
 57f17e6:	0f 10 04 c7          	movups xmm0,XMMWORD PTR [rdi+rax*8]
 57f17ea:	0f 29 44 24 20       	movaps XMMWORD PTR [rsp+0x20],xmm0
 57f17ef:	49 8b 4f 10          	mov    rcx,QWORD PTR [r15+0x10]
 57f17f3:	41 0f 10 07          	movups xmm0,XMMWORD PTR [r15]
 57f17f7:	0f 11 04 c7          	movups XMMWORD PTR [rdi+rax*8],xmm0
 57f17fb:	48 89 4c c7 10       	mov    QWORD PTR [rdi+rax*8+0x10],rcx
 57f1800:	48 8b 44 24 30       	mov    rax,QWORD PTR [rsp+0x30]
 57f1805:	49 89 47 10          	mov    QWORD PTR [r15+0x10],rax
 57f1809:	0f 28 44 24 20       	movaps xmm0,XMMWORD PTR [rsp+0x20]
 57f180e:	41 0f 11 07          	movups XMMWORD PTR [r15],xmm0
 57f1812:	48 8d 45 01          	lea    rax,[rbp+0x1]
 57f1816:	49 ff c5             	inc    r13
 57f1819:	48 39 f0             	cmp    rax,rsi
 57f181c:	0f 82 20 ff ff ff    	jb     57f1742 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556cee>
 57f1822:	49 89 f4             	mov    r12,rsi
 57f1825:	48 ff c5             	inc    rbp
 57f1828:	48 89 e8             	mov    rax,rbp
 57f182b:	4c 8b 74 24 08       	mov    r14,QWORD PTR [rsp+0x8]
 57f1830:	eb 0c                	jmp    57f183e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556bf2>
 57f1832:	48 89 e8             	mov    rax,rbp
 57f1835:	4c 8b 74 24 08       	mov    r14,QWORD PTR [rsp+0x8]
 57f183a:	4c 8b 24 24          	mov    r12,QWORD PTR [rsp]
 57f183e:	4d 39 e5             	cmp    r13,r12
 57f1841:	73 09                	jae    57f184c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556be4>
 57f1843:	4c 39 e8             	cmp    rax,r13
 57f1846:	74 04                	je     57f184c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x556be4>
 57f1848:	4d 89 6e 18          	mov    QWORD PTR [r14+0x18],r13
 57f184c:	48 83 c4 38          	add    rsp,0x38
 57f1850:	5b                   	pop    rbx
 57f1851:	41 5c                	pop    r12
 57f1853:	41 5d                	pop    r13
 57f1855:	41 5e                	pop    r14
 57f1857:	41 5f                	pop    r15
 57f1859:	5d                   	pop    rbp
 57f185a:	c3                   	ret
 57f185b:	48 8d 3d 7e 66 c6 fa 	lea    rdi,[rip+0xfffffffffac6667e]        # 457ee0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f0550>
 57f1862:	48 8d 15 9f f4 cb 00 	lea    rdx,[rip+0xcbf49f]        # 64b0d08 <__register_atfork@plt+0xbf178>
 57f1869:	be 20 00 00 00       	mov    esi,0x20
 57f186e:	ff 15 bc de ce 00    	call   QWORD PTR [rip+0xcedebc]        # 64df730 <__register_atfork@plt+0xedba0>
