ifneq ($(KERNELRELEASE),)
	obj-m := car.o
	car-objs = main.o  source.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order *~
endif
