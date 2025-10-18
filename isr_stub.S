/* my_idt_stub.S */
    .data
    .section .data
    .global tsc_value
    .global irq_count

tsc_value:
    .quad 0                 # 存放最近一次中断触发时的时间戳
irq_count:
    .quad 0                 # 存放中断触发次数

    .section isr_section, "ax", @progbits
    .align 0x1000
    .global my_idt_stub
my_idt_stub:
    # 1. 读取 TSC
    rdtsc                   # EDX:EAX ← 当前时间戳
    shl $32, %rdx           # 左移高 32 位
    or  %rdx, %rax          # 合并为 64 位到 RAX
    movq %rax, tsc_value(%rip)  # 保存到全局变量

    # 2. irq_count++ （增加中断次数）
    movq irq_count(%rip), %rax
    addq $1, %rax
    movq %rax, irq_count(%rip)

    # 3. 发送 EOI（End Of Interrupt）
    mov $0x80b, %ecx
    xor %eax, %eax
    xor %edx, %edx
    wrmsr

    # 4. 返回中断
    iretq
