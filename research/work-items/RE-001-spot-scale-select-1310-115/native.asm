
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005a01310 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x347120>:
 5a01310:	41 57                	push   r15
 5a01312:	41 56                	push   r14
 5a01314:	53                   	push   rbx
 5a01315:	49 89 d7             	mov    r15,rdx
 5a01318:	49 89 f6             	mov    r14,rsi
 5a0131b:	48 89 fb             	mov    rbx,rdi
 5a0131e:	ff 15 54 57 ae 00    	call   QWORD PTR [rip+0xae5754]        # 64e6a78 <__register_atfork@plt+0xf4ee8>
 5a01324:	48 85 c0             	test   rax,rax
 5a01327:	74 06                	je     5a0132f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x347101>
 5a01329:	5b                   	pop    rbx
 5a0132a:	41 5e                	pop    r14
 5a0132c:	41 5f                	pop    r15
 5a0132e:	c3                   	ret
 5a0132f:	b8 01 00 00 00       	mov    eax,0x1
 5a01334:	49 81 ff a0 86 01 00 	cmp    r15,0x186a0
 5a0133b:	0f 82 44 01 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01341:	b8 0a 00 00 00       	mov    eax,0xa
 5a01346:	49 81 ff 40 42 0f 00 	cmp    r15,0xf4240
 5a0134d:	0f 82 32 01 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01353:	b8 64 00 00 00       	mov    eax,0x64
 5a01358:	49 81 ff 80 96 98 00 	cmp    r15,0x989680
 5a0135f:	0f 82 20 01 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01365:	b8 e8 03 00 00       	mov    eax,0x3e8
 5a0136a:	49 81 ff 00 e1 f5 05 	cmp    r15,0x5f5e100
 5a01371:	0f 82 0e 01 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01377:	b8 10 27 00 00       	mov    eax,0x2710
 5a0137c:	49 81 ff 00 ca 9a 3b 	cmp    r15,0x3b9aca00
 5a01383:	0f 82 fc 00 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01389:	4c 89 f9             	mov    rcx,r15
 5a0138c:	48 c1 e9 0a          	shr    rcx,0xa
 5a01390:	b8 a0 86 01 00       	mov    eax,0x186a0
 5a01395:	48 81 f9 f9 02 95 00 	cmp    rcx,0x9502f9
 5a0139c:	0f 82 e3 00 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a013a2:	4c 89 f9             	mov    rcx,r15
 5a013a5:	48 c1 e9 0b          	shr    rcx,0xb
 5a013a9:	b8 40 42 0f 00       	mov    eax,0xf4240
 5a013ae:	48 81 f9 dd 0e e9 02 	cmp    rcx,0x2e90edd
 5a013b5:	0f 82 ca 00 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a013bb:	4c 89 f9             	mov    rcx,r15
 5a013be:	48 c1 e9 0c          	shr    rcx,0xc
 5a013c2:	b8 80 96 98 00       	mov    eax,0x989680
 5a013c7:	48 81 f9 51 4a 8d 0e 	cmp    rcx,0xe8d4a51
 5a013ce:	0f 82 b1 00 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a013d4:	4c 89 f9             	mov    rcx,r15
 5a013d7:	48 c1 e9 0d          	shr    rcx,0xd
 5a013db:	b8 00 e1 f5 05       	mov    eax,0x5f5e100
 5a013e0:	48 81 f9 95 73 c2 48 	cmp    rcx,0x48c27395
 5a013e7:	0f 82 98 00 00 00    	jb     5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a013ed:	48 b9 ff 3f 7a 10 f3 	movabs rcx,0x5af3107a3fff
 5a013f4:	5a 00 00
 5a013f7:	b8 00 ca 9a 3b       	mov    eax,0x3b9aca00
 5a013fc:	49 39 cf             	cmp    r15,rcx
 5a013ff:	0f 86 80 00 00 00    	jbe    5a01485 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fab>
 5a01405:	48 b8 ff 7f c6 a4 7e 	movabs rax,0x38d7ea4c67fff
 5a0140c:	8d 03 00
 5a0140f:	49 39 c7             	cmp    r15,rax
 5a01412:	76 40                	jbe    5a01454 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fdc>
 5a01414:	48 ba ff ff c0 6f f2 	movabs rdx,0x2386f26fc0ffff
 5a0141b:	86 23 00
 5a0141e:	49 39 d7             	cmp    r15,rdx
 5a01421:	76 3d                	jbe    5a01460 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fd0>
 5a01423:	48 ba 00 00 8a 5d 78 	movabs rdx,0x16345785d8a0000
 5a0142a:	45 63 01
 5a0142d:	49 39 d7             	cmp    r15,rdx
 5a01430:	72 3a                	jb     5a0146c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fc4>
 5a01432:	48 ba 00 00 64 a7 b3 	movabs rdx,0xde0b6b3a7640000
 5a01439:	b6 e0 0d
 5a0143c:	49 39 d7             	cmp    r15,rdx
 5a0143f:	72 37                	jb     5a01478 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fb8>
 5a01441:	48 ba 00 00 e8 89 04 	movabs rdx,0x8ac7230489e80000
 5a01448:	23 c7 8a
 5a0144b:	49 39 d7             	cmp    r15,rdx
 5a0144e:	48 0f 42 c1          	cmovb  rax,rcx
 5a01452:	eb 2e                	jmp    5a01482 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fae>
 5a01454:	48 b8 ff e3 0b 54 02 	movabs rax,0x2540be3ff
 5a0145b:	00 00 00
 5a0145e:	eb 22                	jmp    5a01482 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fae>
 5a01460:	48 b8 ff e7 76 48 17 	movabs rax,0x174876e7ff
 5a01467:	00 00 00
 5a0146a:	eb 16                	jmp    5a01482 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fae>
 5a0146c:	48 b8 ff 0f a5 d4 e8 	movabs rax,0xe8d4a50fff
 5a01473:	00 00 00
 5a01476:	eb 0a                	jmp    5a01482 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346fae>
 5a01478:	48 b8 ff 9f 72 4e 18 	movabs rax,0x9184e729fff
 5a0147f:	09 00 00
 5a01482:	48 ff c0             	inc    rax
 5a01485:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
 5a01489:	49 39 f6             	cmp    r14,rsi
 5a0148c:	0f 83 01 01 00 00    	jae    5a01593 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346e9d>
 5a01492:	49 c1 e6 05          	shl    r14,0x5
 5a01496:	48 8b 73 08          	mov    rsi,QWORD PTR [rbx+0x8]
 5a0149a:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
 5a0149e:	4a 8b 4c 36 08       	mov    rcx,QWORD PTR [rsi+r14*1+0x8]
 5a014a3:	48 39 d1             	cmp    rcx,rdx
 5a014a6:	0f 83 da 00 00 00    	jae    5a01586 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346eaa>
 5a014ac:	4a 8b 34 36          	mov    rsi,QWORD PTR [rsi+r14*1]
 5a014b0:	48 39 d6             	cmp    rsi,rdx
 5a014b3:	0f 83 cd 00 00 00    	jae    5a01586 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346eaa>
 5a014b9:	48 8b 7b 20          	mov    rdi,QWORD PTR [rbx+0x20]
 5a014bd:	48 69 c9 58 01 00 00 	imul   rcx,rcx,0x158
 5a014c4:	0f b6 54 0f 49       	movzx  edx,BYTE PTR [rdi+rcx*1+0x49]
 5a014c9:	48 69 ce 58 01 00 00 	imul   rcx,rsi,0x158
 5a014d0:	2a 54 0f 48          	sub    dl,BYTE PTR [rdi+rcx*1+0x48]
 5a014d4:	0f 82 c9 00 00 00    	jb     5a015a3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346e8d>
 5a014da:	b9 01 00 00 00       	mov    ecx,0x1
 5a014df:	75 0d                	jne    5a014ee <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f42>
 5a014e1:	48 39 c1             	cmp    rcx,rax
 5a014e4:	48 0f 42 c1          	cmovb  rax,rcx
 5a014e8:	5b                   	pop    rbx
 5a014e9:	41 5e                	pop    r14
 5a014eb:	41 5f                	pop    r15
 5a014ed:	c3                   	ret
 5a014ee:	0f b6 f2             	movzx  esi,dl
 5a014f1:	40 f6 c6 01          	test   sil,0x1
 5a014f5:	74 0a                	je     5a01501 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f2f>
 5a014f7:	b9 0a 00 00 00       	mov    ecx,0xa
 5a014fc:	83 fe 01             	cmp    esi,0x1
 5a014ff:	74 e0                	je     5a014e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f4f>
 5a01501:	f6 c2 02             	test   dl,0x2
 5a01504:	74 0e                	je     5a01514 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f1c>
 5a01506:	48 6b c9 64          	imul   rcx,rcx,0x64
 5a0150a:	89 f7                	mov    edi,esi
 5a0150c:	83 e7 fe             	and    edi,0xfffffffe
 5a0150f:	83 ff 02             	cmp    edi,0x2
 5a01512:	74 cd                	je     5a014e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f4f>
 5a01514:	f6 c2 04             	test   dl,0x4
 5a01517:	74 11                	je     5a0152a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f06>
 5a01519:	48 69 c9 10 27 00 00 	imul   rcx,rcx,0x2710
 5a01520:	89 f7                	mov    edi,esi
 5a01522:	83 e7 fc             	and    edi,0xfffffffc
 5a01525:	83 ff 04             	cmp    edi,0x4
 5a01528:	74 b7                	je     5a014e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f4f>
 5a0152a:	f6 c2 08             	test   dl,0x8
 5a0152d:	74 11                	je     5a01540 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346ef0>
 5a0152f:	48 69 c9 00 e1 f5 05 	imul   rcx,rcx,0x5f5e100
 5a01536:	89 f7                	mov    edi,esi
 5a01538:	83 e7 f8             	and    edi,0xfffffff8
 5a0153b:	83 ff 08             	cmp    edi,0x8
 5a0153e:	74 a1                	je     5a014e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f4f>
 5a01540:	f6 c2 10             	test   dl,0x10
 5a01543:	0f 84 e0 fd ff ff    	je     5a01329 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x347107>
 5a01549:	48 89 c7             	mov    rdi,rax
 5a0154c:	48 ba ff ff c0 6f f2 	movabs rdx,0x2386f26fc0ffff
 5a01553:	86 23 00
 5a01556:	48 ff c2             	inc    rdx
 5a01559:	48 89 c8             	mov    rax,rcx
 5a0155c:	48 f7 e2             	mul    rdx
 5a0155f:	0f 90 c2             	seto   dl
 5a01562:	83 e6 f0             	and    esi,0xfffffff0
 5a01565:	83 fe 10             	cmp    esi,0x10
 5a01568:	75 13                	jne    5a0157d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346eb3>
 5a0156a:	48 89 c1             	mov    rcx,rax
 5a0156d:	84 d2                	test   dl,dl
 5a0156f:	48 89 f8             	mov    rax,rdi
 5a01572:	0f 84 69 ff ff ff    	je     5a014e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x346f4f>
 5a01578:	e9 ac fd ff ff       	jmp    5a01329 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x347107>
 5a0157d:	48 89 f8             	mov    rax,rdi
 5a01580:	5b                   	pop    rbx
 5a01581:	41 5e                	pop    r14
 5a01583:	41 5f                	pop    r15
 5a01585:	c3                   	ret
 5a01586:	48 8d 3d 4b 53 a7 00 	lea    rdi,[rip+0xa7534b]        # 64768d8 <__register_atfork@plt+0x84d48>
 5a0158d:	ff 15 9d e2 ad 00    	call   QWORD PTR [rip+0xade29d]        # 64df830 <__register_atfork@plt+0xedca0>
 5a01593:	48 8d 15 de 50 a7 00 	lea    rdx,[rip+0xa750de]        # 6476678 <__register_atfork@plt+0x84ae8>
 5a0159a:	4c 89 f7             	mov    rdi,r14
 5a0159d:	ff 15 7d e0 ad 00    	call   QWORD PTR [rip+0xade07d]        # 64df620 <__register_atfork@plt+0xeda90>
 5a015a3:	48 8d 3d 86 54 a7 00 	lea    rdi,[rip+0xa75486]        # 6476a30 <__register_atfork@plt+0x84ea0>
 5a015aa:	ff 15 98 e2 ad 00    	call   QWORD PTR [rip+0xade298]        # 64df848 <__register_atfork@plt+0xedcb8>
