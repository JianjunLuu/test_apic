/* my_idt_stub.S */
    .section isr_data,"aw",@progbits
    .align 0x1000
    .global __ss_irq_fired, __ss_irq_count, nemesis_tsc_aex, __ss_irq_rip, __ss_irq_rax
__ss_irq_fired:
    .int 0x0
__ss_irq_count:
    .int 0x0
nemesis_tsc_aex:
    .quad 0x0;
    /* not sure there's a kernel stack we can use(?) */
__ss_irq_rax:
    .quad 0x0
__ss_irq_rdx:
    .quad 0x0
__ss_irq_rcx:
    .quad 0x0
__ss_irq_rip:
    .quad 0x0




    .section isr_text,"ax",@progbits
    .align 0x1000
    .global my_idt_stub
my_idt_stub:

    cli

    /* Nemesis IRQ latency timestamp */
    mov %rax, __ss_irq_rax(%rip)
    mov %rdx, __ss_irq_rdx(%rip)
    rdtsc
    mov %eax, nemesis_tsc_aex(%rip)
    mov %edx, nemesis_tsc_aex+4(%rip)
    mov %rcx, __ss_irq_rcx(%rip)

    /* IRQ bookkeeping */
    mov 0(%rsp), %rax
    mov %rax, __ss_irq_rip(%rip)
    incl __ss_irq_count(%rip)
    incl __ss_irq_fired(%rip)

    xor %eax,%eax
    xor %edx,%edx
    mov $0x80b, %ecx
    wrmsr

    mov __ss_irq_rax(%rip), %rax
    mov __ss_irq_rdx(%rip), %rdx
    mov __ss_irq_rcx(%rip), %rcx

    sti   
    iretq
