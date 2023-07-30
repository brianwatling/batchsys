#!/bin/sh
# SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
# SPDX-License-Identifier: CC0-1.0

taskset -c 0 ./build/test "${1:-256}" 3>&1 1>&2 2>&3 | cat > /dev/null
