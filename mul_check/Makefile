SHELL := /bin/bash
OPTFLAGS := -O1 -g
CFLAGS := $(OPTFLAGS) -std=c99 -Wall -Wno-unused-function -Wno-strict-aliasing -fno-stack-protector -static
CC := aarch64-linux-gnu-gcc

REMOTE_IP?=192.168.1.161

%: %.c Makefile
	$(CC) -o $@ $(CFLAGS) $<

run_mul_check: mul_check
	scp mul_check ubuntu@$(REMOTE_IP):~
	ssh ubuntu@$(REMOTE_IP) "./mul_check";

run_amplified: amplified
	scp amplified ubuntu@$(REMOTE_IP):~
	ssh ubuntu@$(REMOTE_IP) "time ./amplified";

run_p_check: p_check
	scp p_check ubuntu@$(REMOTE_IP):~
	ssh ubuntu@$(REMOTE_IP) "./p_check";