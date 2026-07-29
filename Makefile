.PHONY: all clean e9patch test test-unit test-integration example

CC       ?= gcc
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude -I.
CFLAGS   ?= -O2 -Wall -Wextra

all: target_program dlopen patch_to_req patcher.so e9patch

target_program: examples/quickstart/target.c
	$(CC) $(CFLAGS) -o $@ $<

dlopen: src/dlopen.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

patch_to_req: src/patch_to_req.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

patcher.so: src/patcher.cpp include/json.hpp
	$(CXX) $(CXXFLAGS) -fPIC -shared -o $@ $< -ldl -pthread

e9patch:
	cd third_party/e9patch && ./build.sh

test: all
	$(MAKE) -C tests test

test-unit: all
	$(MAKE) -C tests test_fork_run test_patcher_run test_concurrent_run \
		test_int3avoid_run test_py

test-integration: all
	$(MAKE) -C tests test_p3_run

example: all
	./examples/quickstart/run.sh

clean:
	rm -f target_program dlopen patch_to_req patcher.so
	cd third_party/e9patch && make clean
	$(MAKE) -C tests clean
