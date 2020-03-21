
CURRENT := $(shell uname -r)
KBUILD := /lib/modules/$(CURRENT)/build
PWD := $(shell pwd)
TMPPWD := /tmp/tlb_invalidator
MODULE := tlb_invalidator

obj-m += $(MODULE).o

build: $(MODULE).c
	mkdir -p $(TMPPWD) 
	cp ./* $(TMPPWD)/
	cd $(TMPPWD)
	$(MAKE) -C $(KBUILD) M=$(TMPPWD) modules

install: build
	sudo insmod $(TMPPWD)/$(MODULE).ko

uninstall:
	sudo rmmod $(MODULE)

clean:
	rm -rf $(TMPPWD)
