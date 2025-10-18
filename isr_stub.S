/* my_idt_stub.S */
    .section .text
    .align 0x10
    .global my_idt_stub
    .extern apic_timer_handler   # 声明 C 函数

my_idt_stub:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    call apic_timer_handler

    # 向 LAPIC 发送 EOI
    mov $0x80b, %ecx
    xor %eax, %eax
    xor %edx, %edx
    wrmsr

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq
