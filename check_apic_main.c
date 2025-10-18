#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <linux/interrupt.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/cpu.h>
#include <linux/irq.h>
//#include <linux/irqdomain.h>
//#include <linux/interrupt.h>
#include <linux/smp.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/special_insns.h>
#include <linux/irqdesc.h> 
#include <asm/irq_vectors.h>
#include <asm/paravirt.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>



MODULE_LICENSE("GPL");

#define IA32_APIC_BASE_MSR 0x1B
#define X2APIC_VERSION_REG 0x803
#define X2APIC_LVT_TIMER   0x832
#define X2APIC_TIMER_INIT  0x838
#define X2APIC_TIMER_CUR   0x839  // Current Count Register
#define X2APIC_EOI        0x80B
#define X2APIC_DIV_CONF 0x83E

#define TIMER_VECTOR 0xEf  // 中断向量,239
#define IA32_PMC0    0x0C1   // PMC0 MSR

#define TIMER_INIT_COUNT   0x100  // 初始计数值，可调整


//保存原状态
/*static gate_desc old_gate;
static bool old_gate_saved = false;
static u64 old_lvt_timer = 0;
static u64 old_init_count = 0;
static bool old_lvt_saved = false;*/

extern void my_idt_stub(void);
extern unsigned long long tsc_value;
extern unsigned long long irq_count;
    //判断handler是否被调用
void trigger_on_cpu0(void *info)
{
    asm volatile("int $0xEF");
    pr_info("handler输出tsc: %llu\n", tsc_value);
    pr_info("handler触发次数: %llu\n", irq_count);

}

static inline void write_idt(struct desc_ptr *dtr)
{
    __asm__ volatile("lidt (%0)" :: "r"(dtr));
}
void read_idt(struct desc_ptr *idtr)
{
    asm volatile ("sidt %0" : "=m" (*idtr)); // 将IDTR内容存入idtr
}
//为当前 IDT 创建一份可写副本
static gate_desc *alloc_writable_idt_copy(struct desc_ptr *idtr)
{
    gate_desc *old_idt, *new_idt;

    // ① 获取当前 IDT 信息
    read_idt(idtr);
    pr_info("[创建idt副本] size = 0x%x (%u bytes), base = 0x%lx\n",
            idtr->size, idtr->size, idtr->address);

    old_idt = (gate_desc *)idtr->address;

    // ② 分配一块新的内核内存，用于可写 IDT 副本
    new_idt = kmalloc(idtr->size + 1, GFP_KERNEL);
    if (!new_idt) {
        pr_err("❌ kmalloc for new_idt failed\n");
        return NULL;
    }

    // ③ 复制原 IDT 内容
    memcpy(new_idt, old_idt, idtr->size + 1);
    pr_info("✅ 成功复制 IDT 到新可写内存: %px\n", new_idt);

    return new_idt;
}
//安装IDT
static void install_idt_entry_on_cpu(void *info)
{
    int entries; //IDT表项个数
    struct desc_ptr idtr;//保存idt的大小和地址

    /*struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed)) ;
*/
    gate_desc g;//门描述符结构体,即 IDT（中断描述符表）中的单个表项

    /*struct gate_struct {
	u16		offset_low;// handler 地址的低 16 位
	u16		segment;
	struct idt_bits	bits;
	u16		offset_middle;// handler 地址的中间 16 位
#ifdef CONFIG_X86_64
	u32		offset_high;// handler 地址的高 32 位（64 位模式下使用）
	u32		reserved;
#endif
} __attribute__((packed));

typedef struct gate_struct gate_desc;
*/
    gate_desc *idt_table;//每个元素对应一个中断向量（0–255）

    //store_idt(&idtr);
    read_idt(&idtr);//使用指令 sidt 读取 IDTR 寄存器的内容
    pr_info("[sidt 读取 IDTR 寄存器的内容] IDTR.size   = 0x%x (%u bytes)\n", idtr.size, idtr.size);
    pr_info("[sidt 读取 IDTR 寄存器的内容，idt的起始虚拟地址] IDTR.base   = 0x%lx\n", idtr.address);
    if (virt_addr_valid(idtr.address))
        pr_info("IDT base is a valid virtual address\n");
    else
        pr_info("IDT base 不在线性映射地址内\n");
    idt_table = (gate_desc *)idtr.address;//让指针指向 IDT 表的起始地址
    entries = (idtr.size + 1) / sizeof(gate_desc);//计算 IDT 表中的表项数量
    pr_info("[指针指向的起始地址] IDT table base = %px, entries = %d\n", idt_table, entries);

    //打印 my_idt_stub 的地址
    unsigned long handler_addr = (unsigned long)&my_idt_stub;
    pr_info("handler地址: 0x%lx\n", handler_addr);

    //扫描 IDT 表，找出空闲的中断向量
    for (int i = 0; i < 256; i++) {
    gate_desc *desc = &idt_table[i];
    unsigned long offset = ((unsigned long)desc->offset_high << 32) |
                           ((unsigned long)desc->offset_middle << 16) |
                           desc->offset_low;
    if (desc->bits.p == 0 || offset == 0) {
        pr_info("IDT[%3d] 空闲，可用\n", i);
    }
}

    
    //读取 IDT 表项内容，验证指针正确性
    for (int i = 236; i < 240; i++) {// 遍历所有可能的中断向量
        gate_desc *desc = &idt_table[i];
        unsigned long offset = ((unsigned long)desc->offset_high << 32) |
                            ((unsigned long)desc->offset_middle << 16) |
                            desc->offset_low;

        pr_info("使用指针作为起始地址读取写入前的IDT[%3d]: offset=0x%016lx segment=0x%04x "
                "type=0x%x dpl=%u p=%u ist=%u "
                "off_low=0x%04x off_mid=0x%04x off_high=0x%08x reserved=0x%08x\n",
                i,
                offset,
                desc->segment,
                desc->bits.type,
                desc->bits.dpl,
                desc->bits.p,
                desc->bits.ist,
                desc->offset_low,
                desc->offset_middle,
                desc->offset_high,
                desc->reserved);
    }

//创建可写 IDT 副本
    gate_desc *new_idt;

        new_idt = alloc_writable_idt_copy(&idtr);
        if (!new_idt) {
            pr_err("创建可写 IDT 副本失败\n");
            return;
        }

        pr_info("新 IDT base的副本地址: %px, 大小: %u bytes\n", new_idt, idtr.size + 1);


//以下是直接修改 idt_table 的方法写入idt
    //gate_desc *desc = &idt_table[TIMER_VECTOR];// 指针指向要改的元素地址

//修改idt副本 new_idt
    gate_desc *desc = &new_idt[TIMER_VECTOR];// 指针指向新副本要改的元素地址
    pr_info("指针指向要改的元素地址 (entry[%02x]) address = %px\n", TIMER_VECTOR, desc);
  
    // 1. 禁止中断修改
    local_irq_disable();
    // 2. 修改 gate 描述符
    desc->offset_low    = handler_addr & 0xFFFF;
    desc->segment       = __KERNEL_CS;  // 通常是 0x10
    desc->bits.ist      = 0;
    desc->bits.type     = 0xE;          // Interrupt Gate
    desc->bits.dpl      = 0;            // 内核态
    desc->bits.p        = 1;
    desc->offset_middle = (handler_addr >> 16) & 0xFFFF;
    desc->offset_high   = (handler_addr >> 32) & 0xFFFFFFFF;
    desc->reserved      = 0;
    // 3. 恢复中断
    local_irq_enable();
    pr_info("[HOOK] IDT[%02x] hooked to 0x%lx\n",  TIMER_VECTOR, handler_addr);
//验证写入结果
    gate_desc *verify_desc = &new_idt[TIMER_VECTOR];
        unsigned long new_offset = ((unsigned long)verify_desc->offset_high << 32) |
                                   ((unsigned long)verify_desc->offset_middle << 16) |
                                   verify_desc->offset_low;

        pr_info("[验证写入结果] IDT[%02x] 描述符内容:\n", TIMER_VECTOR);
        pr_info("  offset = 0x%016lx\n", new_offset);
        pr_info("  segment = 0x%04x\n", verify_desc->segment);
        pr_info("  type = 0x%x, dpl = %u, p = %u, ist = %u\n",
                verify_desc->bits.type,
                verify_desc->bits.dpl,
                verify_desc->bits.p,
                verify_desc->bits.ist);
        pr_info("  off_low = 0x%04x, off_mid = 0x%04x, off_high = 0x%08x, reserved = 0x%08x\n",
                verify_desc->offset_low,
                verify_desc->offset_middle,
                verify_desc->offset_high,
                verify_desc->reserved);

        if (new_offset == handler_addr)
            pr_info("[验证结果] ✅ 写入成功，handler 地址匹配！\n");
        else
            pr_warn("[验证结果] ⚠️ 写入失败：预期 0x%lx, 实际 0x%lx\n",
                    handler_addr, new_offset);


    idtr.address = (unsigned long)new_idt;
    // 使用 lidt 加载新的 IDT到寄存器
    write_idt(&idtr);
    pr_info("[IDT] 已加载新的 IDT 副本，地址 = 0x%lx\n", idtr.address);



    //old_gate = idt_table[TIMER_VECTOR];
    //old_gate_saved = true;


//以下是使用 pack_gate 和 write_idt_entry 的方法写入idt
    //pack_gate(&g, GATE_INTERRUPT, (unsigned long)my_idt_stub,
      //    0, 0, __KERNEL_CS);
    /*声明static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
			     unsigned dpl, unsigned ist, unsigned seg)
*/
    /*pr_info("[配置是否正确] handler=0x%lx\n", (unsigned long)my_idt_stub);
    pr_info("[配置是否正确] gate: low=0x%04x mid=0x%04x high=0x%08x seg=0x%04x type=0x%x dpl=%u p=%u ist=%u\n",
        g.offset_low,
        g.offset_middle,
        g.offset_high,
        g.segment,
        g.bits.type,
        g.bits.dpl,
        g.bits.p,
        g.bits.ist);
    unsigned long final_offset = ((unsigned long)g.offset_high << 32) |
                             ((unsigned long)g.offset_middle << 16) |
                             g.offset_low;
    pr_info("[配置是否正确] reconstructed offset=0x%016lx\n", final_offset);*/


    //write_cr0(read_cr0() & (~X86_CR0_WP));//临时关闭 内核页写保护
    //write_idt_entry(idt_table, TIMER_VECTOR, &g);//写入新的 IDT 表项
    //声明：static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate)
    //write_cr0(read_cr0() | X86_CR0_WP);

    pr_info("cpu %d: IDT vector 0x%x -> my_idt_stub installed\n",
            smp_processor_id(), TIMER_VECTOR);
}

//恢复IDT
/*static void restore_idt_entry_on_cpu(void *arg)
{
    struct desc_ptr idtr;
    gate_desc *idt_table;

    if (!old_gate_saved)
        return;

    store_idt(&idtr);
    idt_table = (gate_desc *)idtr.address;

    write_cr0(read_cr0() & (~X86_CR0_WP));
    write_idt_entry(idt_table, TIMER_VECTOR, &old_gate);
    write_cr0(read_cr0() | X86_CR0_WP);

    pr_info("cpu %d: IDT vector 0x%x restored\n",
            smp_processor_id(), TIMER_VECTOR);
}*/
static int __init check_x2apic_timer_init(void)
{
    u32 eax, ebx, ecx, edx;
    u64 apic_base;
    u64 value;
    bool x2apic_supported;

    
    // 检测 CPU 是否支持 x2APIC
    cpuid(1, &eax, &ebx, &ecx, &edx);
    x2apic_supported = (ecx & (1 << 21)) ? true : false;
    if (!x2apic_supported) {
        pr_info("CPU does NOT support x2APIC\n");
        return -ENODEV;
    }
    pr_info("CPU supports x2APIC\n");

    // 读取 IA32_APIC_BASE MSR
    rdmsrl(IA32_APIC_BASE_MSR, apic_base);
    pr_info("IA32_APIC_BASE MSR: 0x%llx\n", apic_base);
    pr_info("APIC Global Enable (bit11): %llu\n", (apic_base >> 11) & 1);
    pr_info("x2APIC mode (EXTD bit10): %llu\n", (apic_base >> 10) & 1);

    // 读取 Local APIC Version
    rdmsrl(X2APIC_VERSION_REG, value);
    pr_info("x2APIC Version Register: 0x%llx\n", value);
    pr_info("Local APIC Version: 0x%llx\n", value & 0xFF);
    pr_info("Max LVT Entry: %llu\n", (value >> 16) & 0xFF);

    // 注册中断处理函数  
    smp_call_function_single(0, install_idt_entry_on_cpu, NULL, 1);
    //install_idt_entry_on_cpu(NULL);


    // 读取 LVT Timer 寄存器
    rdmsrl(X2APIC_LVT_TIMER, value);
    pr_info("LVT Timer Register (设置前): 0x%llx\n", value);    
    u8 vector;
    u8 mask;
    u8 mode;
    vector = value & 0xFF;          // 0-7 位
    mask   = (value >> 16) & 0x1;   // 16 位
    mode   = (value >> 17) & 0x3;   // 17-18 位

    pr_info("向量 (0-7 bits): 0x%x\n", vector);
    pr_info("Mask (16): 0x%x\n", mask);
    pr_info("模式 (17-18 bits): 0x%x\n", mode);

    // 清除原有向量号 (bits 0–7)
    //value &= ~0xFFULL;
    // 写入新的 TIMER_VECTOR
    //value |= TIMER_VECTOR;
    // 清除原来的17-18位（Timer Mode）
    value &= ~(0x3ULL << 17);
    // 设置为Periodic (01)
    value |= (0x1ULL << 17);
    // 写回寄存器
    wrmsrl(X2APIC_LVT_TIMER, value);

    // 再次读取确认
    rdmsrl(X2APIC_LVT_TIMER, value);
    pr_info("LVT Timer Register (设置完周期模式和vector后): 0x%llx\n", value);
    vector = value & 0xFF;          // 0-7 位
    mask   = (value >> 16) & 0x1;   // 16 位
    mode   = (value >> 17) & 0x3;   // 17-18 位

    pr_info("向量 修改后(0-7 bits): 0x%x\n", vector);
    pr_info("Mask 修改后(16): 0x%x\n", mask);
    pr_info("模式 修改后(17-18 bits): 0x%x\n", mode);

   
    // 设置 Divide Configuration Register
    // 1. 读取设置前的寄存器值
    rdmsrl(X2APIC_DIV_CONF, value);
    pr_info("Divide Configuration Register (设置前): 0x%llx\n", value);
    /*
     Divide Value 对应 bits 0,1,3
     例如要设置为 “Divide by 16” => 011b
     */
    value &= ~0xB;   // 清除 bits [3,1,0] (bit3=0b1000, bit1=0b0010, bit0=0b0001)
    value |= 0x3;    // 设置为 011b => Divide by 16
    // 2. 写入新的配置值
    wrmsrl(X2APIC_DIV_CONF, value);
    // 3. 读取设置后的寄存器值
    rdmsrl(X2APIC_DIV_CONF, value);
    pr_info("Divide Configuration Register (设置后): 0x%llx\n", value);


    // 写入 Initial Count 启动定时器
    wrmsrl(X2APIC_TIMER_INIT, TIMER_INIT_COUNT);
    rdmsrl(X2APIC_TIMER_INIT, value);
    pr_info("Initial Count Register: 0x%llx\n", value);
    
    // 读取 Current Count
    rdmsrl(X2APIC_TIMER_CUR, value);
    pr_info("等待前Current Count Register: 0x%llx\n", value);
    
    pr_info("等待 LAPIC Timer 中断触发中...\n");
    // 延迟等待中断触发
    //msleep(3000);

    // 读取 Current Count
    rdmsrl(X2APIC_TIMER_CUR, value);
    pr_info("等待后Current Count Register: 0x%llx\n", value);

    //确认计时器循环
    for (int i = 0; i < 10; i++) {
    rdmsrl(X2APIC_TIMER_CUR, value);
    pr_info("Current Count: 0x%llx\n", value);
    //msleep(500);
}


    // 停止定时器：设置 Initial Count 为 0或者屏蔽 LVT Timer
    //rdmsrl(X2APIC_LVT_TIMER, value);
    // 设置 Mask 位 (bit 16 = 1)
    //value |= (1ULL << 16);
    //wrmsrl(X2APIC_LVT_TIMER, value);

    //wrmsrl(X2APIC_TIMER_INIT, 0x0); 


// 在 CPU0 上触发
    smp_call_function_single(0, trigger_on_cpu0, NULL, 1);
    
    return 0;
}

static void __exit check_x2apic_timer_exit(void)
{
    pr_info("x2APIC Timer module unloaded\n");
}

module_init(check_x2apic_timer_init);
module_exit(check_x2apic_timer_exit);

