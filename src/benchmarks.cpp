// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

#include <fcntl.h>
#include <liburing.h>
#include <stdlib.h>
#include <unistd.h>

#include <string_view>

#include "batchsys.h"

#define BRINJIN_TEST_MAIN
#include "test.hpp"

using brinjin::strCat;

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

  std::array<int, 3> fds = {};
  for (auto i = 0; i < fds.size(); ++i) {
    fds[i] = open("/tmp", O_TMPFILE | O_WRONLY, S_IRUSR | S_IWUSR);
    REQUIRE(fds[i] >= 0);
  }
  SCOPE_EXIT([=]() {
    for (auto i = 0; i < fds.size(); ++i) {
      batchsys_close_fd(batchsys, fds[i]);
    }
  });

  constexpr size_t kWriteSize = 1024;
  constexpr uint64_t kIterations = 10000;
  constexpr std::chrono::milliseconds kBenchTime(500);

  std::string data(kWriteSize, 'a');
  REQUIRE(data.length() == kWriteSize);

  BENCHMARK_N(strCat("write ", kWriteSize), kBenchTime, kIterations) {
    for (uint64_t i = 0; i < kIterations; ++i) {
      REQUIRE(write(fds[0], data.data(), data.length()) == data.length());
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
  BENCHMARK_N(strCat("batchsys write ", kWriteSize), kBenchTime, kIterations) {
    for (uint64_t i = 0; i < kIterations; ++i) {
      if (!batchsys_push_write(batch, fds[1], data.data(), data.length())) {
        REQUIRE(batch->params.incoming.count == BATCHSYS_MAX_RESULTS);
        postAndCheckResults();
        REQUIRE(batchsys_push_write(batch, fds[1], data.data(), data.length()));
      }
    }
    postAndCheckResults();
  }

  struct io_uring ring;
  SCOPE_EXIT([&]() { io_uring_queue_exit(&ring); });
  constexpr unsigned kQueueDepth = BATCHSYS_MAX_RESULTS;
  REQUIRE(io_uring_queue_init(kQueueDepth, &ring, 0) == 0);

  BENCHMARK_N(strCat("io_uring write ", kWriteSize), kBenchTime, kIterations) {
    uint64_t outstanding = 0;
    for (uint64_t i = 0; i < kIterations; ++i) {
      struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
      if (!sqe) {
        REQUIRE(io_uring_submit(&ring) > 0);
        struct io_uring_cqe* cqe;
        while (!io_uring_peek_cqe(&ring, &cqe)) {
          REQUIRE(cqe->res == data.length());
          io_uring_cqe_seen(&ring, cqe);
          outstanding -= 1;
        }
        sqe = io_uring_get_sqe(&ring);
      }
      io_uring_prep_write(sqe, fds[2], data.data(), data.length(),
                          /*offset=*/0);
      outstanding += 1;
    }
    if (outstanding) {
      REQUIRE(io_uring_submit(&ring) > 0);
    }
    struct io_uring_cqe* cqe;
    while (outstanding) {
      REQUIRE(!io_uring_wait_cqe(&ring, &cqe));
      REQUIRE(cqe->res == data.length());
      io_uring_cqe_seen(&ring, cqe);
      outstanding -= 1;
    }
  }
}