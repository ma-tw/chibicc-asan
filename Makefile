CFLAGS=-std=c11 -g -fno-common -Wall -Wno-switch

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

TEST_SRCS=$(wildcard test/*.c)
TESTS=$(TEST_SRCS:.c=.exe)

ASAN_TEST_SRCS=$(wildcard test/asan/*.c)
ASAN_TESTS=$(ASAN_TEST_SRCS:.c=.exe)

ASAN_LIB=helper/libasan.so

# Stage 1

chibicc: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJS): chibicc.h

$(ASAN_LIB): helper/asan.c include/asan.h
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fPIC -shared -Iinclude -o $@ $<

asan: $(ASAN_LIB)

test/%.exe: chibicc test/%.c
	./chibicc -Iinclude -Itest -c -o test/$*.o test/$*.c
	$(CC) -pthread -o $@ test/$*.o -xc test/common

test: $(TESTS)
	for i in $^; do echo $$i; ./$$i || exit 1; echo; done
	test/driver.sh ./chibicc

test/asan/%.exe: chibicc test/asan/%.c $(ASAN_LIB)
	./chibicc -ftrace -Iinclude -Itest -c -o test/asan/$*.o test/asan/$*.c
	$(CC) -pthread -o $@ test/asan/$*.o -Lhelper -lasan \
	  -Wl,-rpath,'$$ORIGIN/../../helper' -xc test/common

test-asan: $(ASAN_TESTS)
	for i in $^; do echo $$i; LD_PRELOAD=./helper/libasan.so ./$$i || exit 1; echo; done

test-all: test test-stage2

# Stage 2

stage2/chibicc: $(OBJS:%=stage2/%)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

stage2/%.o: chibicc %.c
	mkdir -p stage2/test
	./chibicc -c -o $(@D)/$*.o $*.c

stage2/test/%.exe: stage2/chibicc test/%.c
	mkdir -p stage2/test
	./stage2/chibicc -Iinclude -Itest -c -o stage2/test/$*.o test/$*.c
	$(CC) -pthread -o $@ stage2/test/$*.o -xc test/common

test-stage2: $(TESTS:test/%=stage2/test/%)
	for i in $^; do echo $$i; ./$$i || exit 1; echo; done
	test/driver.sh ./stage2/chibicc

# Misc.

clean:
	rm -rf chibicc tmp* $(TESTS) $(ASAN_TESTS) test/*.s test/*.exe \
	  test/asan/*.s $(ASAN_LIB) stage2
	find * -type f '(' -name '*~' -o -name '*.o' ')' -exec rm {} ';'

.PHONY: asan test clean test-stage2 test-asan
