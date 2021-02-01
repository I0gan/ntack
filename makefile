GCC    := gcc
CFLAGS := -O2
RM     := rm -rf
# src
SYN_SRC := src/syn.c
BENCH_SRC      := src/bench.c

all : bench syn 

clean :
	$(RM) bench syn

bench :
	$(GCC) $(BENCH_SRC) -o $@

syn :
	$(GCC) $(SYN_SRC) -lpthread -o $@

