#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "ftfp.h"
#include "internal.h"

#define NUM_ITRS 2000

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
  uint64_t st; \
  uint64_t end; \
 \
  st = rdtscp(); \
  code; \
  end = rdtscp(); \
 \
  /* Run everything for real, previous was just warmup */ \
 \
  st = rdtscp(); \
  code; \
  end = rdtscp(); \
  result = (end - st);

#define repeat_1(x) x
#define repeat_2(x) repeat_1(x) repeat_1(x)
#define repeat_4(x) repeat_2(x) repeat_2(x)
#define repeat_8(x) repeat_4(x) repeat_4(x)
#define repeat_16(x) repeat_8(x) repeat_8(x)
#define repeat_32(x) repeat_16(x) repeat_16(x)
#define repeat_64(x) repeat_32(x) repeat_32(x)

int use_rand = 1;
fixed rand_fixed() {
  fixed res = 0;
  fixed fix = 0;
  repeat_8({
    res |= rand() & 0xff;
    res <<= 8;
  });
  return MASK_UNLESS(use_rand, res) | MASK_UNLESS(!use_rand, fix);
}

void print_distribution(uint64_t *results, int len) {
  uint64_t next_min = 0;
  while(1) {
    uint64_t min = 0xffffffff;
    for(int i = 0; i < len; i++){
      if(results[i] > next_min && results[i] < min) {
        min = results[i];
      }
    }

    if(min == 0xffffffff) {
      break;
    }

    int count = 0;
    for(int i = 0; i < len; i++) {
      if(results[i] == min) {
        count++;
      }
    }

    printf("%ld\t(%.2lf)\n", min, (double)(count) / len * 100);

    next_min = min;
  }
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

  uint64_t min = 0xffffffff;
  uint64_t max = 0;
  for(int i = 0; i < len; i++) {
    if(results[i] < min) min = results[i];
    if(results[i] > max) max = results[i];
  }

  printf("%s %ld (%ld-%ld, %.2lf%%)\n", name, max_val, min, max, (double)(max_count) / len * 100);
  //print_distribution(results, len);
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

void main(int argc, char* argv[]){
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
