TARGET=realtime_probe
obj-m := realtime_probe.o
realtime_probe-objs:= procfs_helper.o irq_disable_detect.o local_irq_disable_trace.o

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