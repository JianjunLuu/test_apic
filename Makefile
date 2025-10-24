obj-m += check_apic.o
check_apic-objs := check_apic_main.o isr_stub.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

