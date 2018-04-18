ifneq ($(KERNELRELEASE),)
	obj-m := car.o
	car-y := main.o  source.o
	car-y += llc_decap/llc_decap.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	find . -name "*.o" -delete
	rm -rf *.o .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order *~
endif
