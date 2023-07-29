#!/bin/sh

taskset -c 0 ./build/test "${1:-256}" 3>&1 1>&2 2>&3 | cat > /dev/null
