KDIR ?= /lib/modules/$(shell uname -r)/build

all: modules

modules modules_install clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $@

.PHONY: all modules modules_install clean
