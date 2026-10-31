
<stdin>:	file format elf64-x86-64

Disassembly of section .text.__popcountdi2:

0000000000000000 <__popcountdi2>:
       0: 48 89 f8                     	movq	%rdi, %rax
       3: 48 d1 e8                     	shrq	%rax
       6: 48 b9 55 55 55 55 55 55 55 55	movabsq	$0x5555555555555555, %rcx # imm = 0x5555555555555555
      10: 48 21 c1                     	andq	%rax, %rcx
      13: 48 29 cf                     	subq	%rcx, %rdi
      16: 48 89 f8                     	movq	%rdi, %rax
      19: 48 c1 e8 02                  	shrq	$0x2, %rax
      1d: 48 b9 33 33 33 33 33 33 33 33	movabsq	$0x3333333333333333, %rcx # imm = 0x3333333333333333
      27: 48 21 c8                     	andq	%rcx, %rax
      2a: 48 21 f9                     	andq	%rdi, %rcx
      2d: 48 01 c1                     	addq	%rax, %rcx
      30: 48 89 c8                     	movq	%rcx, %rax
      33: 48 c1 e8 04                  	shrq	$0x4, %rax
      37: 48 01 c8                     	addq	%rcx, %rax
      3a: 48 b9 0f 0f 0f 0f 0f 0f 0f 0f	movabsq	$0xf0f0f0f0f0f0f0f, %rcx # imm = 0xF0F0F0F0F0F0F0F
      44: 48 21 c1                     	andq	%rax, %rcx
      47: 48 89 c8                     	movq	%rcx, %rax
      4a: 48 c1 e8 20                  	shrq	$0x20, %rax
      4e: 01 c8                        	addl	%ecx, %eax
      50: 89 c1                        	movl	%eax, %ecx
      52: c1 e9 10                     	shrl	$0x10, %ecx
      55: 01 c1                        	addl	%eax, %ecx
      57: 89 c8                        	movl	%ecx, %eax
      59: c1 e8 08                     	shrl	$0x8, %eax
      5c: 01 c8                        	addl	%ecx, %eax
      5e: 83 e0 7f                     	andl	$0x7f, %eax
      61: c3                           	retq
