#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>

//guess the coin flip that led to these timings
bool guess(uint64_t t1, uint64_t t2) {
    return t1 > t2;
}

uint64_t get_timing(uint64_t op1, uint64_t op2, uint64_t num_itrs) {
    struct timeval start, end;
    uint64_t usec;
    uint64_t a, b, res;

    a = op1;
    b = op2;
    gettimeofday(&start, NULL);
    for(int i = num_itrs; i >= 0; i--){
        __asm__ volatile ("mul %0, %1, %2" : "=r" (res) : "r" (a), "r" (b));
    }
    gettimeofday(&end, NULL);
    
    usec = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);

    return usec;
}

//val2 is assumed to take longer to multiply than val1
//returns true if the coin flip was correctly guessed
bool collect_sample(uint64_t val1, uint64_t val2, uint64_t num_itrs) {
    bool coinflip = rand() % 2;
    uint64_t time1, time2;
    
    time1 = get_timing(coinflip? val2: val1, (uint64_t)-1, num_itrs);
    time2 = get_timing(coinflip? val1: val2, (uint64_t)-1, num_itrs);

    return guess(time1, time2) == coinflip;
}

//returns the success rate
double collect_samples(int num_samples, uint64_t val1, uint64_t val2, uint64_t num_itrs) {
    int successes = 0;
    int failures = 0;

    for(int i = 0; i < num_samples; i++){
        if(collect_sample(val1, val2, num_itrs)) {
            successes++;
        }else{
            failures++;
        }
    }

    return (double)(successes) / (successes + failures);
}

#define SAMPLES_PER_TEST 100
#define ITRS_PER_SAMPLE 100000

#define CSV_SAMPLES 10000

int main(int argc, char* argv[]){

    printf("Trying with %d tests per group and %d iterations per test\n", SAMPLES_PER_TEST, ITRS_PER_SAMPLE);
    printf("Expected values if there is timing variability: 0.5, 0.5, 0.5, 1, 0, 1, 0, 1, 0\n");
    printf("Control group 1: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 0, 0, ITRS_PER_SAMPLE));
    printf("Control group 2: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 16, 1l << 16, ITRS_PER_SAMPLE));
    printf("Control group 3: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 32, 1l << 32, ITRS_PER_SAMPLE));

    printf("Test group 1: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 0, 1l << 32, ITRS_PER_SAMPLE));
    printf("Test group 2: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 32, 0, ITRS_PER_SAMPLE));
    printf("Test group 3: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 16, 1l << 32, ITRS_PER_SAMPLE));
    printf("Test group 4: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 32, 1l << 16 , ITRS_PER_SAMPLE));
    printf("Test group 5: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 31, 1l << 32, ITRS_PER_SAMPLE));
    printf("Test group 6: %0.3lf success rate\n", collect_samples(SAMPLES_PER_TEST, 1l << 32, 1l << 31, ITRS_PER_SAMPLE));

    FILE *fp = fopen("results.csv", "w");
    if(fp == NULL){
        perror("fopen");
    }

    fprintf(fp, "small_mult,large_mult\n");

    for(int i = 0; i < CSV_SAMPLES; i++){
        fprintf(fp, "%ld,%ld\n", get_timing(1 << 16, (uint64_t)-1, ITRS_PER_SAMPLE), get_timing(1l << 32, (uint64_t)-1, ITRS_PER_SAMPLE));
    }

    // fprintf(fp,",");
    // for(int i = 0; i <= 64; i++){
    //     fprintf(fp, "%d,", i);
    // }
    // fprintf(fp, "\n");
    // for(int i = 0; i <= 64; i++){
    //     uint64_t a = i == 64? -1 : (1l << i) - 1;
    //     fprintf(fp, "%d,", i);
    //     for(int j = 0; j <= 64; j++){
    //         uint64_t b = j == 64? -1 : (1l << j) - 1;
            
    //         uint64_t res = get_timing(a, b, ITRS_PER_SAMPLE);

    //         fprintf(fp, "%ld,", res);
    //     }
    //     fprintf(fp, "\n");
    // }

    int res = fclose(fp);
    if(res < 0) {
        perror("fclose");
    }
}
