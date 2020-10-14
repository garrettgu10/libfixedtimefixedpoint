#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "ftfp.h"

#define NUM_ITRS 1000

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
  uint64_t st = rdtscp(); \
  uint64_t end = rdtscp(); \
  uint64_t offset = end-st; \
 \
  st = rdtscp(); \
  code; \
  end = rdtscp(); \
 \
  /* Run everything for real, previous was just warmup */ \
  st = rdtscp(); \
  end = rdtscp(); \
  offset = end-st; \
 \
  st = rdtscp(); \
  code; \
  end = rdtscp(); \
  result = (end - st - offset);

fixed rand_fixed() {
  fixed res = 0;
  // for(int i = 0; i < 8; i++){
  //   res |= rand() & 0xff;
  //   res <<= 8;
  // }
  return res;
}

void print_mode(char *name, uint64_t *results, int len) {
  uint64_t max_val = 0;
  int max_count = 0;
  for(int i = 0; i < len; i++){
    int count = 0;
    for(int j = 0; j < len; j++){
      if(results[j] == results[i]) {
        count++;
      }
    }
    
    if(count > max_count) {
      max_count = count;
      max_val = results[i];
    }
  }

  printf("%s %ld (%.2lf%%)\n", name, max_val, (double)(max_count) / len * 100);
}

void run_test_d(char* name, fixed (*function) (fixed,fixed)){
  uint64_t a, b;
  uint64_t result = 0;
  uint64_t results[NUM_ITRS];
  for(int i = 0; i < NUM_ITRS; i++){
    a = rand_fixed();
    b = rand_fixed();
    TEST_INTERNALS( (*function)(a,b) );
    results[i] = result;
  }
  print_mode(name, results, NUM_ITRS);
}
void run_test_s(char* name, fixed (*function) (fixed)){
  uint64_t a;
  uint64_t result = 0;
  uint64_t results[NUM_ITRS];
  for(int i = 0; i < NUM_ITRS; i++){
    a = rand_fixed();
    TEST_INTERNALS( (*function)(a) );
    results[i] = result;
  }
  print_mode(name, results, NUM_ITRS);
}

void run_test_p(char* name, void (*function) (char*,fixed)){
  char buf[100];
  uint64_t a;
  uint64_t result = 0;
  uint64_t results[NUM_ITRS];
  for(int i = 0; i < NUM_ITRS; i++){
    a = rand_fixed();
    TEST_INTERNALS( (*function)(buf, a) );
    results[i] = result;
  }
  print_mode(name, results, NUM_ITRS);
}

void run_test_sb(char* name, int8_t (*function) (fixed)){
  uint64_t a;
  uint64_t result = 0;
  uint64_t results[NUM_ITRS];
  for(int i = 0; i < NUM_ITRS; i++){
    a = rand_fixed();
    TEST_INTERNALS( (*function)(a) );
    results[i] = result;
  }
  print_mode(name, results, NUM_ITRS);
}

void run_test_db(char* name, int8_t (*function) (fixed,fixed)){
  uint64_t a, b;
  uint64_t result = 0;
  uint64_t results[NUM_ITRS];
  for(int i = 0; i < NUM_ITRS; i++){
    a = rand_fixed();
    b = rand_fixed();
    TEST_INTERNALS( (*function)(a,b) );
    results[i] = result;
  }
  print_mode(name, results, NUM_ITRS);
}


int main(int argc, char* argv[]){
  srand(0);
  printf(    "function ""  cycles\n");
  printf(    "=================\n");
  run_test_s ("fix_neg        ",fix_neg);
  run_test_s ("fix_abs        ",fix_abs);
  run_test_sb("fix_is_neg     ",fix_is_neg);
  run_test_sb("fix_is_nan     ",fix_is_nan);
  run_test_sb("fix_is_inf_pos ",fix_is_nan);
  run_test_sb("fix_is_inf_neg ",fix_is_nan);
  run_test_db("fix_eq         ",fix_eq);
  run_test_db("fix_eq_nan     ",fix_eq_nan);
  run_test_db("fix_cmp        ",fix_cmp);

  printf("\n");

  run_test_d ("fix_add        ",fix_add);
  run_test_d ("fix_sub        ",fix_sub);
  run_test_d ("fix_mul        ",fix_mul);
  run_test_d ("fix_div        ",fix_div);
  printf("\n");

  run_test_s ("fix_floor      ",fix_floor);
  run_test_s ("fix_ceil       ",fix_ceil);
  printf("\n");

  run_test_s ("fix_exp        ",fix_exp);
  run_test_s ("fix_ln         ",fix_ln);
  run_test_s ("fix_log2       ",fix_log2);
  run_test_s ("fix_log10      ",fix_log10);
  printf("\n");

  run_test_d ("fix_pow        ",fix_pow);
  run_test_s ("fix_sqrt       ",fix_sqrt);
  printf("\n");

  run_test_s ("fix_sin        ",fix_sin);
  run_test_s ("fix_cos        ",fix_cos);
  run_test_s ("fix_tan        ",fix_tan);
  //run_test_s ("fix_sin_fast   ",fix_sin_fast,10);
  printf("\n");

  run_test_p ("fix_sprint      ",fix_sprint);
}
