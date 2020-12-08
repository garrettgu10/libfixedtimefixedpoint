#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "ftfp.h"

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

uint64_t ptest(uint64_t a) {
    return fix_sqrt(a);
}

uint64_t collect_sample(uint64_t group) {
    uint64_t st,end;

    st = rdtscp();
    ptest(group);
    end = rdtscp();

    return end-st;
}

void print_mode(uint64_t *results, int len, uint64_t *groups, uint64_t to_count) {
  uint64_t max_val = 0;
  int max_count = 0;
  int total = 0;
  uint64_t sum = 0;
  for(int i = 0; i < len; i++){
    if(groups[i] != to_count || results[i] > 100000) continue;
    total++;
    sum += results[i];

    int count = 0;
    for(int j = 0; j < len; j++){
      if(groups[j] == to_count && results[j] == results[i]) {
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
    if(groups[i] == to_count && results[i] < min) min = results[i];
    if(groups[i] == to_count && results[i] > max) max = results[i];
  }

  printf("group %02ld - mode %ld - avg %.2lf - support %d - (%ld-%ld, %.2lf%%)\n", to_count, max_val, (double)sum / total, total, min, max, (double)(max_count) / total * 100);
}

#define NUM_SAMPLES 10000

int main(int argc, char* argv[]){
    srand(time(NULL));

    uint64_t groups[NUM_SAMPLES];
    uint64_t samples[NUM_SAMPLES];
    
    for(int i = 0; i < NUM_SAMPLES; i++) {
        groups[i] = rand() % 2;
    }

    for(int i = 0; i < NUM_SAMPLES; i++){
        samples[i] = collect_sample(groups[i]);
    }

    print_mode(samples, NUM_SAMPLES, groups, 0);

    print_mode(samples, NUM_SAMPLES, groups, 1);

    printf("%ld %ld\n", ptest(0), ptest(1));
}
