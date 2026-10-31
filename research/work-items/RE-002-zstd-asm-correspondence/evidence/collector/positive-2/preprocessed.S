# 0 "lib/decompress/huf_decompress_amd64.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "lib/decompress/huf_decompress_amd64.S"
# 11 "lib/decompress/huf_decompress_amd64.S"
# 1 "lib/decompress/../common/portability_macros.h" 1
# 149 "lib/decompress/../common/portability_macros.h"
# 1 "/usr/lib/gcc/x86_64-linux-gnu/14/include/cet.h" 1 3 4
# 69 "/usr/lib/gcc/x86_64-linux-gnu/14/include/cet.h" 3 4
 .pushsection ".note.gnu.property", "a"
 .p2align 3
 .long 1f - 0f
 .long 4f - 1f

 .long 5
0:
 .asciz "GNU"
1:
 .p2align 3

 .long 0xc0000002
 .long 3f - 2f
2:

 .long (0x1 | 0x0)
3:
 .p2align 3
4:
 .popsection
# 150 "lib/decompress/../common/portability_macros.h" 2
# 12 "lib/decompress/huf_decompress_amd64.S" 2





.section .note.GNU-stack,"",%progbits
# 54 "lib/decompress/huf_decompress_amd64.S"
.hidden HUF_decompress4X1_usingDTable_internal_fast_asm_loop
.hidden HUF_decompress4X2_usingDTable_internal_fast_asm_loop
.hidden _HUF_decompress4X2_usingDTable_internal_fast_asm_loop
.hidden _HUF_decompress4X1_usingDTable_internal_fast_asm_loop
.global HUF_decompress4X1_usingDTable_internal_fast_asm_loop
.global HUF_decompress4X2_usingDTable_internal_fast_asm_loop
.global _HUF_decompress4X1_usingDTable_internal_fast_asm_loop
.global _HUF_decompress4X2_usingDTable_internal_fast_asm_loop
.text
# 119 "lib/decompress/huf_decompress_amd64.S"
_HUF_decompress4X1_usingDTable_internal_fast_asm_loop:
HUF_decompress4X1_usingDTable_internal_fast_asm_loop:
    endbr64

    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rbp
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15


    movq %rdi, %rax
    movq 0(%rax), %r8
    movq 8(%rax), %r9
    movq 16(%rax), %r10
    movq 24(%rax), %r11
    movq 32(%rax), %rsi
    movq 40(%rax), %rbx
    movq 48(%rax), %rcx
    movq 56(%rax), %rdi
    movq 64(%rax), %rbp
    movq 72(%rax), %rdx
    movq 80(%rax), %r12
    movq 88(%rax), %r13
    movq 96(%rax), %r14
    push %rax
    push 104(%rax)
    push 112(%rax)
    push %r15

    subq $24, %rsp

.L_4X1_compute_olimit:





    movq %rbx, 0(%rsp)
    movq %rdx, 8(%rsp)

    movq 32(%rsp), %rax
    subq %rdi, %rax


    movabsq $-3689348814741910323, %rdx
    mulq %rdx
    movq %rdx, %r15
    shrq $2, %r15

    movq %r8, %rax
    movq 40(%rsp), %rdx
    subq %rdx, %rax
    movq %rax, %rbx


    movabsq $2635249153387078803, %rdx
    mulq %rdx
    subq %rdx, %rbx
    shrq %rbx
    addq %rbx, %rdx
    shrq $2, %rdx


    cmpq %rdx, %r15
    cmova %rdx, %r15


    leaq (%r15, %r15, 4), %r15


    addq %rdi, %r15

    movq 8(%rsp), %rdx
    movq 0(%rsp), %rbx


    movq %rdi, %rax
    cmpq %rax, %r15
    je .L_4X1_exit


    cmpq %r8, %r9
    jb .L_4X1_exit


    cmpq %r9, %r10
    jb .L_4X1_exit


    cmpq %r10, %r11
    jb .L_4X1_exit
# 271 "lib/decompress/huf_decompress_amd64.S"
    movq %r15, 24(%rsp)
    movq %r9, 0(%rsp)
    movq %r10, 8(%rsp)
    movq %r11, 16(%rsp)


    movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d; movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d; movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d; movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d

    .p2align 6

.L_4X1_loop_body:



    movq %r15, %rax; shlxq %r15, %rbp, %rbp; movb %ah, 0(%rsi); movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d; movq %r9, %rax; shlxq %r9, %rdx, %rdx; movb %ah, 0(%rbx); movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d; movq %r10, %rax; shlxq %r10, %r12, %r12; movb %ah, 0(%rcx); movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d; movq %r11, %rax; shlxq %r11, %r13, %r13; movb %ah, 0(%rdi); movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d
    movq %r15, %rax; shlxq %r15, %rbp, %rbp; movb %ah, 1(%rsi); movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d; movq %r9, %rax; shlxq %r9, %rdx, %rdx; movb %ah, 1(%rbx); movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d; movq %r10, %rax; shlxq %r10, %r12, %r12; movb %ah, 1(%rcx); movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d; movq %r11, %rax; shlxq %r11, %r13, %r13; movb %ah, 1(%rdi); movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d
    movq %r15, %rax; shlxq %r15, %rbp, %rbp; movb %ah, 2(%rsi); movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d; movq %r9, %rax; shlxq %r9, %rdx, %rdx; movb %ah, 2(%rbx); movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d; movq %r10, %rax; shlxq %r10, %r12, %r12; movb %ah, 2(%rcx); movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d; movq %r11, %rax; shlxq %r11, %r13, %r13; movb %ah, 2(%rdi); movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d
    movq %r15, %rax; shlxq %r15, %rbp, %rbp; movb %ah, 3(%rsi); movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d; movq %r9, %rax; shlxq %r9, %rdx, %rdx; movb %ah, 3(%rbx); movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d; movq %r10, %rax; shlxq %r10, %r12, %r12; movb %ah, 3(%rcx); movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d; movq %r11, %rax; shlxq %r11, %r13, %r13; movb %ah, 3(%rdi); movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d
    movq %r15, %rax; shlxq %r15, %rbp, %rbp; movb %ah, 4(%rsi); movq %r9, %rax; shlxq %r9, %rdx, %rdx; movb %ah, 4(%rbx); movq %r10, %rax; shlxq %r10, %r12, %r12; movb %ah, 4(%rcx); movq %r11, %rax; shlxq %r11, %r13, %r13; movb %ah, 4(%rdi)





    movq 0(%rsp), %r9
    movq 8(%rsp), %r10
    movq 16(%rsp), %r11




    bsfq %rbp, %rbp; movq %rbp, %rax; andq $7, %rax; shrq $3, %rbp; leaq 5(%rsi), %rsi; subq %rbp, %r8; movq (%r8), %rbp; orq $1, %rbp; shlx %rax, %rbp, %rbp
    movq $53, %r15; shrxq %r15, %rbp, %r15; movzwl (%r14,%r15,2),%r15d

    bsfq %rdx, %rdx; movq %rdx, %rax; andq $7, %rax; shrq $3, %rdx; leaq 5(%rbx), %rbx; subq %rdx, %r9; movq (%r9), %rdx; orq $1, %rdx; shlx %rax, %rdx, %rdx
    movq %r9, 0(%rsp)
    movq $53, %r9; shrxq %r9, %rdx, %r9; movzwl (%r14,%r9,2),%r9d

    bsfq %r12, %r12; movq %r12, %rax; andq $7, %rax; shrq $3, %r12; leaq 5(%rcx), %rcx; subq %r12, %r10; movq (%r10), %r12; orq $1, %r12; shlx %rax, %r12, %r12
    movq %r10, 8(%rsp)
    movq $53, %r10; shrxq %r10, %r12, %r10; movzwl (%r14,%r10,2),%r10d

    bsfq %r13, %r13; movq %r13, %rax; andq $7, %rax; shrq $3, %r13; leaq 5(%rdi), %rdi; subq %r13, %r11; movq (%r11), %r13; orq $1, %r13; shlx %rax, %r13, %r13
    movq %r11, 16(%rsp)
    movq $53, %r11; shrxq %r11, %r13, %r11; movzwl (%r14,%r11,2),%r11d


    cmp %rdi, 24(%rsp)
    ja .L_4X1_loop_body


    movq 0(%rsp), %r9
    movq 8(%rsp), %r10
    movq 16(%rsp), %r11


    jmp .L_4X1_compute_olimit





.L_4X1_exit:
    addq $24, %rsp


    pop %rax
    pop %rax
    pop %rax
    pop %rax


    movq %r8, 0(%rax)
    movq %r9, 8(%rax)
    movq %r10, 16(%rax)
    movq %r11, 24(%rax)
    movq %rsi, 32(%rax)
    movq %rbx, 40(%rax)
    movq %rcx, 48(%rax)
    movq %rdi, 56(%rax)
    movq %rbp, 64(%rax)
    movq %rdx, 72(%rax)
    movq %r12, 80(%rax)
    movq %r13, 88(%rax)


    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    ret

_HUF_decompress4X2_usingDTable_internal_fast_asm_loop:
HUF_decompress4X2_usingDTable_internal_fast_asm_loop:
    endbr64

    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rbp
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    movq %rdi, %rax
    movq 0(%rax), %r8
    movq 8(%rax), %r9
    movq 16(%rax), %r10
    movq 24(%rax), %r11
    movq 32(%rax), %rsi
    movq 40(%rax), %rbx
    movq 48(%rax), %rcx
    movq 56(%rax), %rdi
    movq 64(%rax), %rbp
    movq 72(%rax), %rdx
    movq 80(%rax), %r12
    movq 88(%rax), %r13
    movq 96(%rax), %r14
    push %rax
    push %rax
    push 104(%rax)

    movq 112(%rax), %rax
    push %rax

    movq %rdi, %rax
    push %rax

    movq %rcx, %rax
    push %rax

    movq %rbx, %rax
    push %rax


    subq $8, %rsp

.L_4X2_compute_olimit:





    movq %rdx, 0(%rsp)


    movq %r8, %rax
    movq 40(%rsp), %rdx
    subq %rdx, %rax
    movq %rax, %r15


    movabsq $2635249153387078803, %rdx
    mulq %rdx
    subq %rdx, %r15
    shrq %r15
    addq %r15, %rdx
    shrq $2, %rdx


    movq %rdx, %r15


    movq 8(%rsp), %rax
    subq %rsi, %rax
    movq 16(%rsp), %rdx
    subq %rbx, %rdx

    cmpq %rax, %rdx
    cmova %rax, %rdx

    movq 24(%rsp), %rax
    subq %rcx, %rax

    cmpq %rax, %rdx
    cmova %rax, %rdx

    movq 32(%rsp), %rax
    subq %rdi, %rax

    cmpq %rax, %rdx
    cmova %rax, %rdx

    movabsq $-3689348814741910323, %rax
    mulq %rdx
    shrq $3, %rdx


    cmpq %rdx, %r15
    cmova %rdx, %r15


    movq %r15, %rax
    leaq (%rdi, %rax, 4), %r15
    addq %rax, %r15

    movq 0(%rsp), %rdx


    movq %rdi, %rax
    cmpq %rax, %r15
    je .L_4X2_exit


    cmpq %r8, %r9
    jb .L_4X2_exit


    cmpq %r9, %r10
    jb .L_4X2_exit


    cmpq %r10, %r11
    jb .L_4X2_exit
# 526 "lib/decompress/huf_decompress_amd64.S"
    movq %r15, 48(%rsp)

    .p2align 6

.L_4X2_loop_body:

    movq %r8, 0(%rsp)


    movq %rbp, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rsi); shlxq %r15, %rbp, %rbp; addq %rax, %rsi; movq %rdx, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rbx); shlxq %r15, %rdx, %rdx; addq %rax, %rbx; movq %r12, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rcx); shlxq %r15, %r12, %r12; addq %rax, %rcx; movq %r13, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rdi); shlxq %r15, %r13, %r13; addq %rax, %rdi
    movq %rbp, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rsi); shlxq %r15, %rbp, %rbp; addq %rax, %rsi; movq %rdx, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rbx); shlxq %r15, %rdx, %rdx; addq %rax, %rbx; movq %r12, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rcx); shlxq %r15, %r12, %r12; addq %rax, %rcx; movq %r13, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rdi); shlxq %r15, %r13, %r13; addq %rax, %rdi
    movq %rbp, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rsi); shlxq %r15, %rbp, %rbp; addq %rax, %rsi; movq %rdx, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rbx); shlxq %r15, %rdx, %rdx; addq %rax, %rbx; movq %r12, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rcx); shlxq %r15, %r12, %r12; addq %rax, %rcx; movq %r13, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rdi); shlxq %r15, %r13, %r13; addq %rax, %rdi
    movq %rbp, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rsi); shlxq %r15, %rbp, %rbp; addq %rax, %rsi; movq %rdx, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rbx); shlxq %r15, %rdx, %rdx; addq %rax, %rbx; movq %r12, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rcx); shlxq %r15, %r12, %r12; addq %rax, %rcx; movq %r13, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rdi); shlxq %r15, %r13, %r13; addq %rax, %rdi
    movq %rbp, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rsi); shlxq %r15, %rbp, %rbp; addq %rax, %rsi; movq %rdx, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rbx); shlxq %r15, %rdx, %rdx; addq %rax, %rbx; movq %r12, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rcx); shlxq %r15, %r12, %r12; addq %rax, %rcx; movq %r13, %rax; shrq $53, %rax; movzwl 0(%r14,%rax,4),%r8d; movzbl 2(%r14,%rax,4),%r15d; movzbl 3(%r14,%rax,4),%eax; movw %r8w, (%rdi); shlxq %r15, %r13, %r13; addq %rax, %rdi


    movq 0(%rsp), %r8

    bsfq %rbp, %rbp; movq %rbp, %rax; shrq $3, %rbp; andq $7, %rax; subq %rbp, %r8; movq (%r8), %rbp; orq $1, %rbp; shlxq %rax, %rbp, %rbp; bsfq %rdx, %rdx; movq %rdx, %rax; shrq $3, %rdx; andq $7, %rax; subq %rdx, %r9; movq (%r9), %rdx; orq $1, %rdx; shlxq %rax, %rdx, %rdx; bsfq %r12, %r12; movq %r12, %rax; shrq $3, %r12; andq $7, %rax; subq %r12, %r10; movq (%r10), %r12; orq $1, %r12; shlxq %rax, %r12, %r12; bsfq %r13, %r13; movq %r13, %rax; shrq $3, %r13; andq $7, %rax; subq %r13, %r11; movq (%r11), %r13; orq $1, %r13; shlxq %rax, %r13, %r13

    cmp %rdi, 48(%rsp)
    ja .L_4X2_loop_body
    jmp .L_4X2_compute_olimit



.L_4X2_exit:
    addq $8, %rsp

    pop %rax
    pop %rax
    pop %rax
    pop %rax
    pop %rax
    pop %rax
    pop %rax


    movq %r8, 0(%rax)
    movq %r9, 8(%rax)
    movq %r10, 16(%rax)
    movq %r11, 24(%rax)
    movq %rsi, 32(%rax)
    movq %rbx, 40(%rax)
    movq %rcx, 48(%rax)
    movq %rdi, 56(%rax)
    movq %rbp, 64(%rax)
    movq %rdx, 72(%rax)
    movq %r12, 80(%rax)
    movq %r13, 88(%rax)


    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    ret
