obj-m := husky.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -L /usr/include -C $(KDIR) M=$(PWD) modules
 
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
