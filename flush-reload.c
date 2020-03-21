#include <stdlib.h>
#include <stdio.h>
#include <immintrin.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>

#define PG_SIZE (4096U*1)
#define NUM_EXPR 5000

volatile char *oraclearr;
volatile unsigned *tmp_store;
volatile unsigned char* addr1;
volatile unsigned char* addr2;
int offset = 12;

unsigned long long averg[256];


static inline void clflush(void* addr){
    // __asm__ __volatile__ ("\tclflush (%0)\n"::"r"(addr));
    asm volatile("\tclflush (%0)\n" : :"r"(addr) : "memory");
}


void flush_all(){
    for(int i = 0; i < 256; ++i){
        clflush((void*)oraclearr + PG_SIZE * i);
    }
}

void void_operations1(int64_t *a, int64_t *b);

void void_operations3(volatile char* a, volatile unsigned char* b){
    addr1[offset] = 0xf0;
    volatile char *f = &a[PG_SIZE * b[offset]];
    *f = 0x0;
};

void void_operations2(int64_t *a, int64_t *b){
    while(*a > *b){
        *a -= *b;
    }
    if(b>a) void_operations1(b, a); 
    else void_operations3(oraclearr, addr1);
    return;
}

void void_operations1(int64_t *a, int64_t *b){
    while(*a > *b){
        *a -= *b;
    }

    if(b>a) void_operations2(b, a);
    else void_operations3(oraclearr, addr1);
    return;
}

static unsigned long long rdtscp() {
	unsigned long long a, d;
	asm volatile ("rdtscp" : "=a" (a), "=d" (d));
	a = (d<<32) | a;
	return a;
}

uint64_t time_access(volatile void* addr1){
	uint64_t t1, t2;
	volatile char *f = (volatile char*)addr1;
	t1 = rdtscp();
	*f;	
	t2 = rdtscp();	
	return (t2 - t1);
}


extern uint64_t Te0[256];
int main(void){
    register char loaded_val;
    volatile char *f;
    int64_t a = 100000000,b = 100;
    addr1 = (char*)(((uint64_t)malloc(20*PG_SIZE) + PG_SIZE) & ~0xFFF );
    addr2 = addr1;
    oraclearr = malloc(sizeof(char) * PG_SIZE*1024);
    tmp_store = malloc(sizeof(unsigned));
    for(int i = 0; i < NUM_EXPR; ++i){
	int flag = 0;
        for(unsigned int j = 0; j < 256; ++j){	
            f = oraclearr + PG_SIZE * addr2[offset];
            asm volatile("\tclflush (%0)\n"::"r"(&oraclearr[PG_SIZE * j]));
            asm volatile("\tclflush (%0)\n"::"r"(&oraclearr[PG_SIZE * rand()%256]));
            asm volatile("\tclflush (%0)\n"::"r"(&oraclearr[PG_SIZE * rand()%256]));
            // flush_all();
            void_operations1(&a, &b);
            // asm volatile("mfence");
            // *f;
		    averg[j] += time_access((void*)(oraclearr + PG_SIZE * j));
	    }
    
    }

    for(int i = 0; i < 256; ++i){
	    printf("BYTE 0x%02x : %4lu us\n", i, averg[i] / NUM_EXPR);
    }
    return 1;
}
