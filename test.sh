make clean
make
sudo insmod check_apic.ko
sudo rmmod check_apic
sudo dmesg | tail -n 50


