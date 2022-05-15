TARGET=procfs_test
obj-m := $(TARGET).o

KDIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules
install:
	insmod $(TARGET).ko
uninstall:
	rmmod $(TARGET).ko
clean:
	make -C $(KDIR) M=$(PWD) clean