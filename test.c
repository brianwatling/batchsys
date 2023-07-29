#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "batchsys.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

uint64_t timediff(struct timespec* start, struct timespec* end) {
  return (end->tv_sec - start->tv_sec) * 1000000000LL + end->tv_nsec -
         start->tv_nsec;
}

void bench(char* argv) {
  size_t len = strlen(argv);
  printf("starting benchmark to write %d bytes\n", (int)len);
  struct timespec start, end, t;
  int batchsys = batchsys_open();
  if (!batchsys) {
    printf("failed to open batchsys: %d\n", errno);
    return;
  }
  int fd = open("/tmp/batchsys_benchmark.txt", O_CREAT | O_TRUNC | O_WRONLY,
                S_IRUSR | S_IWUSR);
  if (fd < 0) {
    batchsys_close(batchsys);
    printf("failed to open temp file: %d\n", errno);
    return;
  }
  struct BatchSysBatch* batch = batchsys_batch_alloc(batchsys);
  clock_gettime(CLOCK_MONOTONIC, &start);
  int count = 0;
  int i;
  int ret = 0;
  int j;
  for (i = 0; i < 10000; ++i) {
    batchsys_batch_reset(batch);
    while (batchsys_push_write(batch, fd, argv, len)) {
      ++count;
    }
    ret = batchsys_post_batch(batchsys, batch);
    assert(batch->params.outgoing.count > 0);
    for (j = 0; j < batch_batch_result_count(batch); ++j) {
      const struct SyscallResult* result = batch_batch_get_result(batch, j);
      if (result->result < 0) {
        printf("write failure: %zd %ld\n", result->result, result->error);
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  uint64_t batched = timediff(&start, &end);
  printf("batched: %" PRIu64 "\n", timediff(&start, &end));
  printf("ret: %d errno: %d\n", ret, errno);
  batchsys_batch_free(batch);

  clock_gettime(CLOCK_MONOTONIC, &start);
  for (i = 0; i < count; ++i) {
    int x = write(fd, argv, len);
    (void)x;
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  uint64_t single = timediff(&start, &end);
  printf("single:  %" PRIu64 "\n", single);
  printf("batch/single: %lf\n", (double)batched / single);
  batchsys_close_fd(batchsys, fd);
  batchsys_close(batchsys);
}

int main(int argc, char* argv[]) {
  char* arg = "hello\n";
  if (argc > 1) {
    uint16_t count = atoi(argv[1]);
    arg = malloc(count);
    memset(arg, 'a', count);
    arg[count - 1] = 0;
  }
  bench(arg);
  bench(arg);
  bench(arg);
  bench(arg);
  bench(arg);
  bench(arg);
  return 0;
}
