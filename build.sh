#!/bin/sh
set -ex
g++ -std=c++17 src/dlopen.cpp -o dlopen
g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -I. -o patch_to_req src/patch_to_req.cpp
g++ -std=c++17 -O2 -fPIC -shared -Iinclude -I. src/patcher.cpp -o patcher.so -ldl -pthread

cd third_party/e9patch

sudo ./build.sh
