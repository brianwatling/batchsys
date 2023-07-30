// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

#include "batchsys.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <string_view>

#define BRINJIN_TEST_MAIN
#include "test.hpp"

TEST_CASE(Basic) {
  int batchsys = batchsys_open();
  REQUIRE(batchsys >= 0);
  SCOPE_EXIT([=]() {
    REQUIRE(batchsys_cached_fds(batchsys) == 0);
    batchsys_close(batchsys);
  });

  batchsys_batch_t* batch = batchsys_batch_alloc(batchsys);
  REQUIRE(batch);
  SCOPE_EXIT([=]() { batchsys_batch_free(batch); });

  char pattern[] = "/tmp/batchsys_tmp.XXXXXX";
  int fd = mkstemp(pattern);
  REQUIRE(fd >= 0);
  SCOPE_EXIT([=]() { batchsys_close_fd(batchsys, fd); });

  std::string_view hello = "hello!";
  REQUIRE(batchsys_push_write(batch, fd, hello.data(), hello.length()));
  REQUIRE(batchsys_push_write(batch, fd, hello.data(), hello.length()));

  REQUIRE(batchsys_post_batch(batchsys, batch) == 2);

  REQUIRE(batchsys_cached_fds(batchsys) == 1);
  REQUIRE(batchsys_close_fd(batchsys, fd) == 0);
  REQUIRE(batchsys_cached_fds(batchsys) == 0);

  REQUIRE(batch_batch_result_count(batch) == 2);
  for (uint64_t i = 0; i < batch_batch_result_count(batch); ++i) {
    syscall_result_t result = *batch_batch_get_result(batch, i);
    REQUIRE(result.result == hello.length());
    REQUIRE(!result.error);
  }

  int check = open(pattern, O_RDONLY);
  REQUIRE(check >= 0);
  SCOPE_EXIT([=]() { batchsys_close_fd(batchsys, check); });

  std::vector<char> buffer(1024);
  const auto got = read(check, buffer.data(), buffer.size());
  REQUIRE(got == hello.length() * 2);
  REQUIRE(std::string_view(buffer.data(), got) == "hello!hello!");
}

TEST_CASE(Benchmark) {
  int batchsys = batchsys_open();
  REQUIRE(batchsys >= 0);
  SCOPE_EXIT([=]() {
    REQUIRE(batchsys_cached_fds(batchsys) == 0);
    batchsys_close(batchsys);
  });

  batchsys_batch_t* batch = batchsys_batch_alloc(batchsys);
  REQUIRE(batch);
  SCOPE_EXIT([=]() { batchsys_batch_free(batch); });

  int fd1 = open("/tmp", O_TMPFILE | O_WRONLY, S_IRUSR | S_IWUSR);
  REQUIRE(fd1 >= 0);
  SCOPE_EXIT([=]() { batchsys_close_fd(batchsys, fd1); });

  int fd2 = open("/tmp", O_TMPFILE | O_WRONLY, S_IRUSR | S_IWUSR);
  REQUIRE(fd2 >= 0);
  SCOPE_EXIT([=]() { close(fd2); });

  constexpr size_t kWriteSize = 1024;
  constexpr uint64_t kIterations = 1000;
  constexpr std::chrono::milliseconds kBenchTime(500);

  std::string data(kWriteSize, 'a');
  REQUIRE(data.length() == kWriteSize);

  BENCHMARK_N("write", kBenchTime, kIterations) {
    for (uint64_t i = 0; i < kIterations; ++i) {
      REQUIRE(write(fd2, data.data(), data.length()) == data.length());
    }
  }

  auto postAndCheckResults = [&]() {
    REQUIRE(batchsys_post_batch(batchsys, batch) ==
            batch->params.incoming.count);
    for (uint64_t j = 0; j < batch_batch_result_count(batch); ++j) {
      const syscall_result_t* result = batch_batch_get_result(batch, j);
      REQUIRE(result->result == data.length());
    }
    batchsys_batch_reset(batch);
  };
  BENCHMARK_N("batchsys write", kBenchTime, kIterations) {
    for (uint64_t i = 0; i < kIterations; ++i) {
      if (!batchsys_push_write(batch, fd1, data.data(), data.length())) {
        REQUIRE(batch->params.incoming.count == BATCHSYS_MAX_RESULTS);
        postAndCheckResults();
        REQUIRE(batchsys_push_write(batch, fd1, data.data(), data.length()));
      }
    }
    postAndCheckResults();
  }
}