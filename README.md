<!--
SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
SPDX-License-Identifier: CC0-1.0
-->

![Ubuntu Build](https://github.com/brianwatling/batchsys/actions/workflows/cmake.yml/badge.svg)
[![REUSE compliant](https://api.reuse.software/badge/github.com/brianwatling/batchsys)](https://api.reuse.software/info/github.com/brianwatling/batchsys)

# Batchsys

A kernel module for batching system calls.

## Status

Experimental. Works with Linux Kernel 5.19. `read()`, `write()`, and `close()` are implemented, other system calls are TODO. Needs automated tests.

### Performance

Performance wins from batching system calls depend on how expensive each system call is. Batchsys can be up to 75% faster than normal system call on maximum size batches of cheap system calls (ex. write one byte repeatedly). For writes of 1 Kb the speedup from batching is around 15%.

## Details/Motivation

Originally inspired by [MegaPipe: A New Programming Interface for Scalable Network I/O](https://people.eecs.berkeley.edu/~sylvia/papers/osdi2012_megapipe.pdf).

Batchsys allows user space to build a batch of system calls and hand them off to the kernel for synchronous execution. Batchsys allocates buffers shared between user spaces and kernel space - userspace writes requests and reads responses while kernel space reads requests and writes responses. System calls are executed synchronously and sequentially when a batch is sent to the kernel, meaning results are available immediately without waiting for a completion event.

### !!!Safety Concern!!!

Batchsys will attempt to cache kernel-internal structures for any file descriptor passed in a Batchsys batch. This is done to avoid overhead of the file table in the kernel. This caching means userspace must close file descriptors used with Batchsys via either `batchsys_close_fd()` or by batching a `close()` call with `batchsys_push_close()` to keep Batchsys's cache coherent (otherwise batchsys will continue referencing and using the original file).

## Usage

Open a Batchsys handle with `batchsys_open()`. The result is a file descriptor that should be closed via `batchsys_close()` (or plain `close()`).

```c
#include <batchsys.h>

int batchsys = batchsys_open();

batchsys_close(batchsys);
```

Allocate a batch buffer via `batchsys_batch_alloc()`. Batch buffers can and should be reused - simply call `batchsys_batch_reset()` after flushing a batch (reset is very cheap compared to allocating a new batch). Batch buffers must be freed by calling `batchsys_batch_free()`.

```c
batchsys_batch_t* batch = batchsys_batch_alloc(batchsys);

batchsys_batch_free(batch);
```

Push one or several requests into the batch via the `batchsys_push_xxx()` APIs. The `batchsys_push_xxx()` functions will return falsey (zero) if the batch is full and must be flushed. You can check if a batch is full or empty via `batchsys_batch_full()` and `batchsys_batch_empty()` respectively. Up to `BATCHSYS_MAX_RESULTS` requests can fit into a single batch. Flush the batch for processing via `batchsys_post_batch()` when the batch is full or you've pushed as much as you'd like. Note that the batch must be reset via `batchsys_batch_reset()` before being reused.

```c
// Assume these are initialized elsewhere.
int batchsys;
batchsys_batch_t* batch;

const char* data = "hello world!"
size_t len = strlen(data);

// Batch 3 writes into a single system call.
batchsys_push_write(batch, fd1, data, len);
batchsys_push_write(batch, fd2, data, len);
batchsys_push_write(batch, fd3, data, len);
batchsys_post_batch(batchsys, batch);
batchsys_batch_reset(batch);
```

Batchsys returns system call results directly in the batch buffer. The normal return code and errno for each system call in a batch are returned and can be accessed via `syscall_result_t`. Use the `batch_batch_result_count()` and `batch_batch_get_result()` functions to access results (or read results directly via `batchsys_batch_t`, everything is accessible).

```c
// Assume these are initialized elsewhere.
int batchsys;
batchsys_batch_t* batch;

int flush_batch_and_check_results() {
    if (batchsys_post_batch(batchsys, batch) < 0) {
        return -1;
    }
    for (int i = 0; i < batch_batch_result_count(batch); ++i) {
        const syscall_result_t* result = batch_batch_get_result(batch, i);
        if (result->result < 0) {
            printf("Got an error on syscall %d: result= %zd errno=%ld\n", result->result, result->errno);
            return -1;
        }
    }
    return 0;
}

The following example builds on all of the above to build a simple function that writes some data to an arbitrary number of file descriptors in batches.

```c
// Assume these are initialized elsewhere.
int batchsys;
batchsys_batch_t* batch;

int write_to_many(size_t num_fds, int* fds, const void* data, size_t len) {
    for (size_t i = 0; i < num_fds; ++i) {
        if (batchsys_batch_full(batch)) {
            if (flush_batch_and_check_results() < 0) {
                // Either posting failed or one of the write()s failed.
                return -1;
            }
        }
        int ret = batchsys_push_write(batch, fds[i], data, len);
        (void)ret;
        assert(ret && "We checked batchsys_batch_full() so push will never fail");
    }
    return flush_batch_and_check_results();
}
```

## Build

Dependencies: Requires only Kernel headers for your kernel.

```bash
sudo apt-get install linux-headers-$(uname -r)
```

Compile:

```bash
cmake -B build/ .
cmake --build build/ -j
```

Install kernel module:

```
sudo insmod build/batchsys.ko
```

## License

MIT License

Copyright (c) 2023 Brian Watling
