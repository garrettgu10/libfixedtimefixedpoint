SHELL := /bin/bash
OPTFLAGS := -O1 -g -fno-aggressive-loop-optimizations
CFLAGS := $(OPTFLAGS) -std=c99 -Wall -Werror -Wno-unused-function -Wno-strict-aliasing -fno-stack-protector -fno-plt
LDFLAGS := -lcmocka -lm -lftfp
CC := aarch64-linux-gnu-gcc

LD_LIBRARY_PATH=.

progs             := test perf_test generate_test_helper
libs              := libftfp.so
ftfp_src          := ftfp.c autogen.c internal.c cordic.c power.c debug.c double.c
ftfp_inc          := ftfp.h internal.h base.h lut.h
ftfp_obj          := $(ftfp_src:.c=.o)
ftfp_pre          := $(ftfp_src:.c=.pre)

autogens          := base.h lut.h autogen.c base.pyc

test_ftfp_src     := test.c
test_ftfp_obj     := $(test_ftfp_src:.c=.o)
test_ftfp_pre     := $(test_ftfp_src:.c=.pre)

perf_ftfp_src     := perf_test.c
perf_ftfp_obj     := $(perf_ftfp_src:.c=.o)
perf_ftfp_pre     := $(perf_ftfp_src:.c=.pre)

gen_test_src     := generate_test_helper.c
gen_test_obj     := $(gen_test_src:.c=.o)
gen_test_pre     := $(gen_test_src:.c=.pre)

.PHONY: all clean depend alltest
all: $(libs)

base.h : generate_base.py
	python3 generate_base.py --file base.h
base.py : generate_base.py
	python3 generate_base.py --pyfile base.py

autogen.c : generate_print.py base.py
	python3 generate_print.py --file autogen.c
lut.h : generate_base.py
	python3 generate_base.py --lutfile lut.h

%.o: %.c ${ftfp_inc} Makefile
	if [[ "$<" = "test.c" ]]; then \
		$(CC) -c -o $@ $(CFLAGS) -march=armv8-a $<; \
	else \
		$(CC) -c -o $@ $(CFLAGS) -ffreestanding -march=armv8-a+nosimd $<; \
	fi

libftfp.so: $(ftfp_obj) $(dbl_obj)
	$(CC) ${CFLAGS} -march=armv8-a+nosimd -shared -o $@ $+

perf_test: $(perf_ftfp_obj) $(libs)
	$(CC) -lftfp -L . -o $@ $(CFLAGS) $< ${LDFLAGS}

cycle_test: cycle_test.o $(libs)
	$(CC) -lftfp -L . -o $@ $(CFLAGS) $< ${LDFLAGS}

test: $(test_ftfp_obj) $(libs)
	$(CC) -L . ${CFLAGS} -o $@ $< ${LDFLAGS}

generate_test_helper: $(gen_test_obj) $(libs)
	$(CC) -L . ${CFLAGS} -o $@ $< ${LDFLAGS}

pre: $(test_ftfp_pre) $(ftfp_pre) $(perf_ftfp_pre) $(gen_test_pre)

%.pre: %.c Makefile
	$(CC) -c -E -o $@ $(CFLAGS) $<

clean:
	$(RM) -r $(progs) $(libs) $(ftfp_obj) $(test_ftfp_obj) $(test_ftfp_pre) ${perf_ftfp_obj} ${perf_ftfp_pre} ${gen_test_obj} ${gen_test_pre} ${autogens}

run_tests:
	set -x ; \
	number=1 ; while [[ $$number -le 61  ]] ; do \
		echo "Testing" $$number "int bits..." && make clean && python -B generate_base.py --file base.h --pyfile base.py --intbits $$number && make test && LD_LIBRARY_PATH=. QEMU_LD_PREFIX=/usr/aarch64-linux-gnu qemu-aarch64 ./test || exit 1; \
		((number = number + 1)) ; \
	done

run_tests_remote:
	set -x ; \
	number=1 ; while [[ $$number -le 61  ]] ; do \
		echo "Testing" $$number "int bits..." && make clean && python -B generate_base.py --file base.h --pyfile base.py --intbits $$number && make test && scp libftfp.so test ubuntu@192.168.1.3:~ && ssh ubuntu@192.168.1.3 "LD_LIBRARY_PATH=. ./test" || exit 1; \
		((number = number + 1)) ; \
	done

run_generate_test_helper:
	set -x ; \
	echo "#ifndef TEST_HELPER_H" > test_helper.h ; \
	echo "#define TEST_HELPER_H" >> test_helper.h ; \
	number=1 ; while [[ $$number -le 61  ]] ; do \
		make clean && python -B generate_base.py --file base.h --pyfile base.py --intbits $$number && make generate_test_helper && ./generate_test_helper; \
		((number = number + 1)) ; \
	done ; \
	echo >> test_helper.h ; \
	echo "#endif" >> test_helper.h ;
