#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "ftfp.h"

#define PERF_ITRS 2000000

static inline uint64_t rdtscp(){
  uint64_t v;
#ifdef __aarch64__
  __asm__ volatile("mrs %0, pmccntr_el0" : "=r" (v));
#else //x86_64
  __asm__ volatile("rdtscp;"
                   "shl $32,%%rdx;"
                   "or %%rdx,%%rax;"
                   : "=a" (v)
                   :
                   : "%rcx","%rdx");
#endif

  return v;
}

#define TEST_INTERNALS( code ) \
  int ctr = 0; \
  uint64_t st = rdtscp(); \
  /* Offset for running the loop and rdtscp */ \
  for(ctr=0;ctr<PERF_ITRS;ctr++){ \
  } \
  uint64_t end = rdtscp(); \
  uint64_t offset = end-st; \
 \
  st = rdtscp(); \
  for(ctr=0;ctr<PERF_ITRS;ctr++){ \
    code; \
  } \
  end = rdtscp(); \
 \
  /* Run everything for real, previous was just warmup */ \
  st = rdtscp(); \
  for(ctr=0;ctr<PERF_ITRS;ctr++){ \
  } \
  end = rdtscp(); \
  offset = end-st; \
 \
  st = rdtscp(); \
  for(ctr=0;ctr<PERF_ITRS;ctr++){ \
    code; \
  } \
  end = rdtscp(); \
  printf("%s  %" PRIu64 "\n",name,(end-st-offset)/PERF_ITRS);

void run_test_d(char* name, fixed (*function) (fixed,fixed), fixed a, fixed b){
  TEST_INTERNALS( (*function)(a,b) );
}
void run_test_s(char* name, fixed (*function) (fixed), fixed a){
  TEST_INTERNALS( (*function)(a) );
}

void run_test_p(char* name, void (*function) (char*,fixed), fixed a){
  char buf[100];
  TEST_INTERNALS( (*function)(buf, a); )
}

void run_test_sb(char* name, int8_t (*function) (fixed), fixed a){
  TEST_INTERNALS( (*function)(a); )
}

void run_test_db(char* name, int8_t (*function) (fixed,fixed), fixed a, fixed b){
  TEST_INTERNALS( (*function)(a, b); )
}

fixed fix_abs(fixed op1) {  
  uint8_t xpos =  !FIX_TOP_BIT(op1);
  uint64_t absx = MASK_UNLESS_64( xpos,   op1) |
                  MASK_UNLESS_64(!xpos, (~op1)+1 );
  return absx;
}


int main(int argc, char* argv[]){
  printf(    "function ""  cycles\n");
  printf(    "=================\n");
  run_test_s ("fix_abs        ",fix_abs,10);
}
