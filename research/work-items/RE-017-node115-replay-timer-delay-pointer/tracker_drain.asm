
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005afa030 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e400>:
 5afa030:	55                   	push   rbp
 5afa031:	41 57                	push   r15
 5afa033:	41 56                	push   r14
 5afa035:	41 55                	push   r13
 5afa037:	41 54                	push   r12
 5afa039:	53                   	push   rbx
 5afa03a:	48 83 ec 48          	sub    rsp,0x48
 5afa03e:	49 89 f6             	mov    r14,rsi
 5afa041:	48 89 fb             	mov    rbx,rdi
 5afa044:	48 8d 7e 60          	lea    rdi,[rsi+0x60]
 5afa048:	48 8b 46 78          	mov    rax,QWORD PTR [rsi+0x78]
 5afa04c:	31 f6                	xor    esi,esi
 5afa04e:	48 2d e8 03 00 00    	sub    rax,0x3e8
 5afa054:	48 0f 43 f0          	cmovae rsi,rax
 5afa058:	48 89 74 24 38       	mov    QWORD PTR [rsp+0x38],rsi
 5afa05d:	48 c7 44 24 40 00 00 	mov    QWORD PTR [rsp+0x40],0x0
 5afa064:	00 00
 5afa066:	49 8d 46 48          	lea    rax,[r14+0x48]
 5afa06a:	49 8d b6 88 00 00 00 	lea    rsi,[r14+0x88]
 5afa071:	48 89 14 24          	mov    QWORD PTR [rsp],rdx
 5afa075:	4c 89 74 24 08       	mov    QWORD PTR [rsp+0x8],r14
 5afa07a:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 5afa07f:	48 89 74 24 18       	mov    QWORD PTR [rsp+0x18],rsi
 5afa084:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
 5afa089:	48 8d 44 24 40       	lea    rax,[rsp+0x40]
 5afa08e:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 5afa093:	48 8d 44 24 38       	lea    rax,[rsp+0x38]
 5afa098:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
 5afa09d:	48 89 e6             	mov    rsi,rsp
 5afa0a0:	e8 9b 64 2e ff       	call   4de0540 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf67ef0>
 5afa0a5:	49 8b 46 58          	mov    rax,QWORD PTR [r14+0x58]
 5afa0a9:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 5afa0ae:	41 0f 10 46 48       	movups xmm0,XMMWORD PTR [r14+0x48]
 5afa0b3:	0f 29 04 24          	movaps XMMWORD PTR [rsp],xmm0
 5afa0b7:	49 c7 46 48 00 00 00 	mov    QWORD PTR [r14+0x48],0x0
 5afa0be:	00
 5afa0bf:	49 c7 46 50 08 00 00 	mov    QWORD PTR [r14+0x50],0x8
 5afa0c6:	00
 5afa0c7:	49 c7 46 58 00 00 00 	mov    QWORD PTR [r14+0x58],0x0
 5afa0ce:	00
 5afa0cf:	4c 8b 74 24 10       	mov    r14,QWORD PTR [rsp+0x10]
 5afa0d4:	4d 85 f6             	test   r14,r14
 5afa0d7:	74 2a                	je     5afa103 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e32d>
 5afa0d9:	4c 8b 64 24 08       	mov    r12,QWORD PTR [rsp+0x8]
 5afa0de:	49 8d ac 24 88 00 00 	lea    rbp,[r12+0x88]
 5afa0e5:	00
 5afa0e6:	45 31 ff             	xor    r15d,r15d
 5afa0e9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 5afa0f0:	48 83 7d 98 00       	cmp    QWORD PTR [rbp-0x68],0x0
 5afa0f5:	74 2e                	je     5afa125 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e30b>
 5afa0f7:	49 ff c7             	inc    r15
 5afa0fa:	48 83 c5 68          	add    rbp,0x68
 5afa0fe:	4d 39 fe             	cmp    r14,r15
 5afa101:	75 ed                	jne    5afa0f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e340>
 5afa103:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
 5afa108:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
 5afa10c:	0f 28 04 24          	movaps xmm0,XMMWORD PTR [rsp]
 5afa110:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
 5afa113:	48 89 d8             	mov    rax,rbx
 5afa116:	48 83 c4 48          	add    rsp,0x48
 5afa11a:	5b                   	pop    rbx
 5afa11b:	41 5c                	pop    r12
 5afa11d:	41 5d                	pop    r13
 5afa11f:	41 5e                	pop    r14
 5afa121:	41 5f                	pop    r15
 5afa123:	5d                   	pop    rbp
 5afa124:	c3                   	ret
 5afa125:	4d 8d 6f 01          	lea    r13,[r15+0x1]
 5afa129:	48 8d 7d 80          	lea    rdi,[rbp-0x80]
 5afa12d:	e8 fe 36 01 00       	call   5b0d830 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x23ac00>
 5afa132:	eb 55                	jmp    5afa189 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e2a7>
 5afa134:	48 8d 45 e0          	lea    rax,[rbp-0x20]
 5afa138:	49 6b cf 68          	imul   rcx,r15,0x68
 5afa13c:	48 8b 50 60          	mov    rdx,QWORD PTR [rax+0x60]
 5afa140:	49 89 54 0c 60       	mov    QWORD PTR [r12+rcx*1+0x60],rdx
 5afa145:	0f 10 40 50          	movups xmm0,XMMWORD PTR [rax+0x50]
 5afa149:	41 0f 11 44 0c 50    	movups XMMWORD PTR [r12+rcx*1+0x50],xmm0
 5afa14f:	0f 10 40 40          	movups xmm0,XMMWORD PTR [rax+0x40]
 5afa153:	41 0f 11 44 0c 40    	movups XMMWORD PTR [r12+rcx*1+0x40],xmm0
 5afa159:	0f 10 00             	movups xmm0,XMMWORD PTR [rax]
 5afa15c:	0f 10 48 10          	movups xmm1,XMMWORD PTR [rax+0x10]
 5afa160:	0f 10 50 20          	movups xmm2,XMMWORD PTR [rax+0x20]
 5afa164:	0f 10 58 30          	movups xmm3,XMMWORD PTR [rax+0x30]
 5afa168:	41 0f 11 5c 0c 30    	movups XMMWORD PTR [r12+rcx*1+0x30],xmm3
 5afa16e:	41 0f 11 54 0c 20    	movups XMMWORD PTR [r12+rcx*1+0x20],xmm2
 5afa174:	41 0f 11 4c 0c 10    	movups XMMWORD PTR [r12+rcx*1+0x10],xmm1
 5afa17a:	41 0f 11 04 0c       	movups XMMWORD PTR [r12+rcx*1],xmm0
 5afa17f:	49 ff c7             	inc    r15
 5afa182:	49 ff c5             	inc    r13
 5afa185:	48 83 c5 68          	add    rbp,0x68
 5afa189:	4d 39 f5             	cmp    r13,r14
 5afa18c:	73 12                	jae    5afa1a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e290>
 5afa18e:	48 83 7d 00 00       	cmp    QWORD PTR [rbp+0x0],0x0
 5afa193:	75 9f                	jne    5afa134 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e2fc>
 5afa195:	48 8d 7d e8          	lea    rdi,[rbp-0x18]
 5afa199:	e8 92 36 01 00       	call   5b0d830 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x23ac00>
 5afa19e:	eb e2                	jmp    5afa182 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e2ae>
 5afa1a0:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 5afa1a5:	e9 59 ff ff ff       	jmp    5afa103 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e32d>
 5afa1aa:	48 89 c3             	mov    rbx,rax
 5afa1ad:	eb 06                	jmp    5afa1b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x24e27b>
 5afa1af:	48 89 c3             	mov    rbx,rax
 5afa1b2:	49 ff c5             	inc    r13
 5afa1b5:	4d 29 ee             	sub    r14,r13
 5afa1b8:	49 6b f5 68          	imul   rsi,r13,0x68
 5afa1bc:	4c 01 e6             	add    rsi,r12
 5afa1bf:	49 6b ff 68          	imul   rdi,r15,0x68
 5afa1c3:	4c 01 e7             	add    rdi,r12
 5afa1c6:	49 6b d6 68          	imul   rdx,r14,0x68
 5afa1ca:	ff 15 98 53 9e 00    	call   QWORD PTR [rip+0x9e5398]        # 64df568 <__register_atfork@plt+0xed9d8>
 5afa1d0:	4d 01 fe             	add    r14,r15
 5afa1d3:	4c 89 74 24 10       	mov    QWORD PTR [rsp+0x10],r14
 5afa1d8:	48 89 e7             	mov    rdi,rsp
 5afa1db:	e8 80 6c 01 00       	call   5b10e60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2375d0>
 5afa1e0:	48 89 df             	mov    rdi,rbx
 5afa1e3:	e8 68 68 8f 00       	call   63f0a50 <_Unwind_Resume@plt>
 5afa1e8:	ff 15 d2 52 9e 00    	call   QWORD PTR [rip+0x9e52d2]        # 64df4c0 <__register_atfork@plt+0xed930>
