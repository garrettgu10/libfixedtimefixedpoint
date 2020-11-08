#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

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

#define NUM_TESTS 100000
uint64_t counts[NUM_TESTS];
uint64_t operands[NUM_TESTS];
uint64_t results[NUM_TESTS];
uint8_t bits[NUM_TESTS];

void print_mode(uint64_t *results, int len, uint8_t to_count) {
  uint64_t max_val = 0;
  int max_count = 0;
  int total = 0;
  uint64_t sum = 0;
  for(int i = 0; i < len; i++){
    if(bits[i] != to_count || results[i] > 300) continue;
    total++;
    sum += results[i];

    int count = 0;
    for(int j = 0; j < len; j++){
      if(bits[j] == to_count && results[j] == results[i]) {
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
    if(bits[i] == to_count && results[i] < min) min = results[i];
    if(bits[i] == to_count && results[i] > max) max = results[i];
  }

  printf("%02dbits - mode %ld - avg %.2lf - support %d - (%ld-%ld, %.2lf%%)\n", to_count, max_val, (double)sum / total, total, min, max, (double)(max_count) / total * 100);
}

uint64_t mul(uint64_t a, uint64_t b){
    return a * b;
}

int main(int argc, char* argv[]){
    srand(0);

    for(int i = 0; i < NUM_TESTS; i++){
        bits[i] = rand() % 64;
        operands[i] = (1l << (bits[i]));
    }

    counts[0] = rdtscp();
    for(int i = 0; i < NUM_TESTS; i++){
        results[i] = mul(operands[i], 0x9b74eda8435e5a6);
        counts[i + 1] = rdtscp();
    }

    for(int i = 0; i < NUM_TESTS; i++){
        results[i] = counts[i + 1] - counts[i];
    }

    for(int i = 0; i < 64; i++){
        print_mode(results, NUM_TESTS, i);
    }
}
