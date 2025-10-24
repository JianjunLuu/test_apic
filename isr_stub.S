/* my_idt_stub.S */
    .section .text
    .align 0x10
    .global my_idt_stub
    .extern apic_timer_handler   # 声明 C 函数
    .extern __ss_irq_fired    #是否触发中断

my_idt_stub:
    pushq %rax
    pushq %rcx
    pushq %rdx
  

    call apic_timer_handler

    # 向 LAPIC 发送 EOI
    mov $0x80b, %ecx
    xor %eax,%eax
    xor %edx,%edx
    wrmsr


    popq %rdx
    popq %rcx
    popq %rax

    
    iretq
