/* isr_stub.S */
.text
.global my_idt_stub
.type my_idt_stub, @function

my_idt_stub:
    /* 保存寄存器 */
    pushq  %rax
    pushq  %rbx
    pushq  %rcx
    pushq  %rdx
    pushq  %rsi
    pushq  %rdi
    pushq  %rbp
    pushq  %r8
    pushq  %r9
    pushq  %r10
    pushq  %r11
    pushq  %r12
    pushq  %r13
    pushq  %r14
    pushq  %r15

    /* 调用 C 回调 */
    callq my_isr_c_handler

    /* 恢复寄存器 */
    popq  %r15
    popq  %r14
    popq  %r13
    popq  %r12
    popq  %r11
    popq  %r10
    popq  %r9
    popq  %r8
    popq  %rbp
    popq  %rdi
    popq  %rsi
    popq  %rdx
    popq  %rcx
    popq  %rbx
    popq  %rax

    iretq
.size my_idt_stub, .-my_idt_stub
