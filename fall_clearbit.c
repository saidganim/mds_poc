#include <stdlib.h>
#include <stdio.h>
#include <immintrin.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <fcntl.h>
#define __USE_GNU
#include <signal.h>
#include <ucontext.h>
#define PG_SIZE (4096U*1)
#define NUM_EXPR 1
#define NUM_ROUNDS 1
#define TENREP(a)     a;a;a;a;a;a;a;a;a;a
#define HUNDREDREP(a) TENREP(TENREP(a))
#define HUNDREDREP1(a) HUNDREDREP(HUNDREDREP(a))
#define CACHELSZ 64
#define PRIME_PREFETCH 457
#define L3CACHESZ (PG_SIZE*4096)
#define STORE_BUFFER_ENTRIES 81U

volatile char *oraclearr;
volatile char *shdworaclearr;
volatile unsigned *tmp_store;
volatile unsigned char* addr1;
volatile unsigned char* addr2;
volatile unsigned char* addr3;
volatile unsigned char* addr4;
volatile unsigned char* addr5;
volatile unsigned char* addr6;
volatile unsigned char* addr7;
volatile unsigned char* addr8;


// volatile unsigned char addr1[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr2[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr3[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr4[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr5[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr6[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr7[PG_SIZE*200]__attribute__((aligned(4096)));
// volatile unsigned char addr8[PG_SIZE*200]__attribute__((aligned(4096)));

volatile unsigned char** aadr1;
volatile unsigned char** aadr2;
int tlb_fd;
int shadow_offset[1024];
const int offset = 0xfa;
int shadow_offset[1024];
int shift = 0;
volatile unsigned char store_buffer[4096*STORE_BUFFER_ENTRIES] __attribute__((aligned(4096)));
uint64_t averg[256];
int64_t averg_rnd[256];


size_t memsize;
void* mem;

void tlb_flush_all(){
    pwrite(tlb_fd, 0x0, 100, 0x0);
}

void clear_accessed_bit(void* vaddr){
    pwrite(tlb_fd, vaddr, 100, 0x0);
}

void evict_l1_cache(volatile void *addr){
		for(int i = 0; i < memsize; i += 4096){
			volatile char* ptr = (volatile char*)((((uint64_t)mem + i) & (~0xfff) | (uint64_t)addr & 0xfff));
			*ptr;*ptr;
		}
}

static inline void clflush(void* addr){
    // __asm__ __volatile__ ("\tclflush (%0)\n"::"r"(addr));
    asm volatile("\tclflush (%0)\n" : :"r"(addr) : "memory");
}


void flush_all(){
    for(int i = 0; i < 256; ++i){
        clflush((void*)oraclearr + PG_SIZE * i + i);
    }
}

void void_operations1(int64_t *a, int64_t *b);

static inline void memaccess(void* p){
    volatile char* addr = (volatile char*) p;
    *addr;
}

void __attribute__((optimize("-O0")))void_operations3(volatile char* a, volatile unsigned char* b){
    // asm volatile("mfence");
    // addr1[offset] = 0xfc;
    // addr8[offset] = 0xfa;
    /*
    store_buffer[4096*0 + offset] = 0xfc;
    store_buffer[4096*1 + offset] = 0xfc;
    store_buffer[4096*2 + offset] = 0xfc;
    store_buffer[4096*3 + offset] = 0xfc;
    store_buffer[4096*4 + offset] = 0xfc;
    store_buffer[4096*5 + offset] = 0xfc;
    store_buffer[4096*6 + offset] = 0xfc;
    store_buffer[4096*7 + offset] = 0xfc;
    store_buffer[4096*8 + offset] = 0xfc;
    store_buffer[4096*9 + offset] = 0xfc;
    store_buffer[4096*10 + offset] = 0xfc;
    store_buffer[4096*11 + offset] = 0xfc;
    store_buffer[4096*12 + offset] = 0xfc;
    store_buffer[4096*13 + offset] = 0xfc;
    store_buffer[4096*14 + offset] = 0xfc;
    store_buffer[4096*15 + offset] = 0xfc;
    store_buffer[4096*16 + offset] = 0xfc;
    store_buffer[4096*17 + offset] = 0xfc;
    store_buffer[4096*18 + offset] = 0xfc;
    store_buffer[4096*19 + offset] = 0xfc;
    store_buffer[4096*20 + offset] = 0xfc;
    store_buffer[4096*21 + offset] = 0xfc;
    store_buffer[4096*22 + offset] = 0xfc;
    store_buffer[4096*23 + offset] = 0xfc;
    store_buffer[4096*24 + offset] = 0xfc;
    store_buffer[4096*25 + offset] = 0xfc;
    store_buffer[4096*26 + offset] = 0xfc;
    store_buffer[4096*27 + offset] = 0xfc;
    store_buffer[4096*28 + offset] = 0xfc;
    store_buffer[4096*29 + offset] = 0xfc;
    store_buffer[4096*30 + offset] = 0xfc;
    store_buffer[4096*31 + offset] = 0xfc;
    store_buffer[4096*32 + offset] = 0xfc;
    store_buffer[4096*33 + offset] = 0xfc;
    store_buffer[4096*34 + offset] = 0xfc;
    store_buffer[4096*35 + offset] = 0xfc;
    store_buffer[4096*36 + offset] = 0xfc;
    store_buffer[4096*37 + offset] = 0xfc;
    store_buffer[4096*38 + offset] = 0xfc;
    store_buffer[4096*39 + offset] = 0xfc;
    store_buffer[4096*40 + offset] = 0xfc;
    store_buffer[4096*41 + offset] = 0xfc;
    store_buffer[4096*42 + offset] = 0xfc;
    store_buffer[4096*43 + offset] = 0xfc;
    store_buffer[4096*44 + offset] = 0xfc;
    store_buffer[4096*45 + offset] = 0xfc;
    store_buffer[4096*46 + offset] = 0xfc;
    store_buffer[4096*47 + offset] = 0xfc;
    store_buffer[4096*48 + offset] = 0xfc;
    store_buffer[4096*49 + offset] = 0xfc;
    store_buffer[4096*50 + offset] = 0xfc;
    store_buffer[4096*51 + offset] = 0xfc;
    store_buffer[4096*52 + offset] = 0xfc;
    store_buffer[4096*53 + offset] = 0xfc;
    store_buffer[4096*54 + offset] = 0xfc;
    store_buffer[4096*55 + offset] = 0xfc;
    store_buffer[4096*56 + offset] = 0xfc;
    store_buffer[4096*57 + offset] = 0xfc;
    store_buffer[4096*58 + offset] = 0xfc;
    store_buffer[4096*59 + offset] = 0xfc;
    store_buffer[4096*60 + offset] = 0xfc;
    store_buffer[4096*61 + offset] = 0xfc;
    store_buffer[4096*62 + offset] = 0xfc;
    store_buffer[4096*63 + offset] = 0xfc;
    store_buffer[4096*64 + offset] = 0xfc;
    store_buffer[4096*65 + offset] = 0xfc;
    store_buffer[4096*66 + offset] = 0xfc;
    store_buffer[4096*67 + offset] = 0xfc;
    store_buffer[4096*68 + offset] = 0xfc;
    store_buffer[4096*69 + offset] = 0xfc;
    store_buffer[4096*70 + offset] = 0xfc;
    store_buffer[4096*71 + offset] = 0xfc;
    store_buffer[4096*72 + offset] = 0xfc;
    store_buffer[4096*73 + offset] = 0xfc;
    store_buffer[4096*74 + offset] = 0xfc;
    store_buffer[4096*75 + offset] = 0xfc;
    store_buffer[4096*76 + offset] = 0xfc;
    store_buffer[4096*77 + offset] = 0xfc;
    store_buffer[4096*77 + offset] = 0xfc;
    store_buffer[4096*78 + offset] = 0xfc;
    store_buffer[4096*79 + offset] = 0xfc;
    store_buffer[4096*80 + offset] = 0xfc;
    */
    // asm volatile("mfence");
    // for(int i = 0; i < 12; ++i)sched_yield();

    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // // oraclearr[PG_SIZE * addr3[offset]];
    // // oraclearr[PG_SIZE * addr2[offset]];
    // oraclearr[PG_SIZE * addr2[offset]];

    //  asm volatile("mfence");
    // volatile unsigned char *ad1 = &;
    // // volatile unsigned char *ad2 = (volatile unsigned char*)(&(addr4[offset]));
    // // volatile unsigned char *ad3 = (volatile unsigned char*)(&(addr5[offset]));
    // // volatile unsigned char *ad4 = (volatile unsigned char*)(&(addr6[offset]));
    // // volatile unsigned char *ad5 = (volatile unsigned char*)(&(addr7[offset]));
    // volatile unsigned char *ad6 = &;

    // for(int i = 0; i < 12; ++i) sched_yield();
    // printf("ad1 : %p \nad2 : %p\n =====================\n", ad1, ad2);
    // addr6[offset] = 0x09;
    // addr4[offset] = 0xfc;
    // addr5[offset] = 0xfc;
    // addr7[offset] = 0xfc;
    //asm volatile("sfence");
    addr1[offset];
    asm volatile ("lfence");
    //addr8[offset*2+1] = 0xf8;
    //void* pp = &(addr8[offset*2+1]);
    //pp = (void*) ((uint64_t)pp & 0xfff);

    //*((volatile char*)addr1+(uint64_t)pp) = 0xf1;
    //asm volatile("sfence");
    //addr6[offset] = 0xf6;
    //addr7[offset] = 0xdd;
    // *(ad2) = 0xf2;
    // *(ad3) = 0xf3;
    // *(ad4) = 0xf4;
    // *(ad5) = 0xf5;
  
    // addr1[offset] = 0x09;
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];
    // oraclearr[PG_SIZE * addr3[offset]];

    //oraclearr[PG_SIZE * addr3[offset]];
    //oraclearr[PG_SIZE * addr3[offset]];

    oraclearr[PG_SIZE * addr2[offset]];
   
};

void void_operations2(int64_t *a, int64_t *b){
    while(*a > *b){
        *a -= *b;
    }
    if(b>a) void_operations1(b, a); 
    else void_operations3(oraclearr, addr2);
    return;
}

void void_operations1(int64_t *a, int64_t *b){
    while(*a > *b){
        *a -= *b;
    }

    if(b>a) void_operations2(b, a);
    else void_operations3(oraclearr, addr2);
    return;
}

static unsigned long long rdtscp() {
	unsigned long long a, d;
	asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
	a = (d<<32) | a;
	return a;
}

uint64_t time_access(volatile void* add){
	uint64_t t1, t2;
	volatile char *f = (volatile char*)add;
    // for(int i=0; i < 12; ++i)sched_yield();
	t1 = rdtscp();
	*f;	
	t2 = rdtscp();	
	return (t2 - t1);
}

int  __attribute__((optimize("-O0")))main(void){
    register char loaded_val;
    volatile char *f;
    int64_t a = 100000000,b = 100;

    addr1 = (char*)(((uint64_t)malloc(200*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr2 = (char*)(((uint64_t)malloc(200*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr3 = (char*)(((uint64_t)malloc(200*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr4 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr6 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr5 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr7 = (char*)(((uint64_t)malloc(200*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr8 = (char*)(((uint64_t)malloc(200*PG_SIZE) + PG_SIZE) & ~0xFFF );
    // aadr1 = &addr1;
    // aadr2 = &addr8;
    // addr1[offset] = 0xff;
    tlb_fd = open("/dev/tlb_invalidator", O_WRONLY, 0x0);
    if(tlb_fd == -1){
    	printf("FILE DOESNT EXIST\n");
	return 1;
    }
    memsize = sysconf(_SC_PAGESIZE) * 1024;
	mem = (malloc(memsize));
    oraclearr = malloc(sizeof(char) * PG_SIZE*1024);
    tmp_store = malloc(sizeof(unsigned));
    // EVERYTHING IS INITIALIZED
experiments_:
    // printf("Running experiments\n");
    memset(averg_rnd, 0x0, 256*sizeof(int64_t));
    memset(averg, 0x0, 256*sizeof(uint64_t));
    memset(oraclearr, 0x1,  PG_SIZE*1024);

    addr3[offset] = 0x34;
    addr2[offset] = 0x34;
    addr1[offset] = 0xf1;
    for(int rnd_i = 0; rnd_i < NUM_ROUNDS; ++rnd_i){
        memset(averg, 0x0, 256*sizeof(uint64_t));
        for(int i = 0; i < NUM_EXPR; ++i){
            // evict_full_cache();
            int flag = 0;
            shift = 0;
            for(unsigned int j = 0; j < 256; ++j){
                asm volatile("\tclflush (%0)\n"::"r"((void*)&oraclearr[PG_SIZE * j]));
            }

            // asm volatile("\tclflush (%0)\n"::"r"((void*)&addr1));
            // asm volatile("\tclflush (%0)\n"::"r"((void*)&addr8));
            clear_accessed_bit((void*)&addr2[offset]);
            asm volatile("\tclflush (%0)\n"::"r"((void*)&addr2[offset]));
            // clear_accessed_bit((void*)&addr8[offset]);
            tlb_flush_all();
            void_operations1(&a, &b);
            for(unsigned int j = 0; j < 256; ++j){
                averg[j] += time_access((void*)(oraclearr + PG_SIZE * j));
            }
        }
        uint64_t min = (uint64_t)-1;
        int minid = -1;
        for(int rn = 0; rn < 256; ++rn){
            if((averg[rn]/NUM_EXPR) <= (min - 1) && rn > 0 && rn != addr3[offset]){
                min = averg[rn]/NUM_EXPR;
                minid = rn;
            }
        }
        ++averg_rnd[minid];
    }
    int winner;
    int64_t winner_max = -1;
    int64_t winner_min = 0xfffffffe;
    for(int i = 0; i < 256; ++i){
        if(averg_rnd[i] > winner_max){
            winner_max = averg_rnd[i];
            winner = i;
        }
        if(averg_rnd[i] < winner_min){
            winner_min = averg_rnd[i];
        }
	    // printf("BYTE 0x%02x : %4lu wins : %4lu us\n", i, averg_rnd[i], averg[i]/NUM_EXPR);
    }
    if(averg[winner]>= 200) {
        // printf("Not egnough confidence\n");
        goto experiments_;
    }
    // printf("ADRESSES WERE [%p] vs [%p]\n", &addr1[offset], &addr2[offset]);
    printf("0x%02x\n", winner, winner);
    return 1;
}

//
//
