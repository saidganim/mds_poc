CC = gcc
CFLAGS = -g3 -O0

user:  fall_TAA.c fall_TLBMISS.c fall_clearbit.c
	$(CC) fall_TAA.c $(CFLAGS) -o taasupress
	$(CC) fall_TLBMISS.c $(CFLAGS) -o tlbmiss
	$(CC) fall_clearbit.c $(CFLAGS) -o clearbit




build:  user
	$(MAKE) module_install

module_install:
	$(MAKE) install -C tlb/

clean:
	$(MAKE) clean -C tlb/
	rm tlbmiss taasupress clearbit
