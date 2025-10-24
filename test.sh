make clean
make
sudo dmesg -C
sudo insmod check_apic.ko
sudo rmmod check_apic
sudo dmesg | tail -n 50


