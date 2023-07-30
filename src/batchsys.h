// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

#ifndef BATCHSYS_H_
#define BATCHSYS_H_

#ifdef __KERNEL__
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/types.h>

// clang-format off
#include <linux/eventpoll.h>
// clang-format on

#else
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define BATCHSYS_STATIC_ASSERT(expr, msg) static_assert(expr, #msg)
#else
#define BATCHSYS_STATIC_ASSERT(expr, msg) _Static_assert(expr, #msg)
#endif

enum Syscall {
  kAccept,
  kAccept4,
  kAccept4NonBlockReuse,
  kRead,
  kPread,
  kReadv,
  kRecv,
  kRecvfrom,
  kWrite,
  kPwrite,
  kWritev,
  kSend,
  kSendto,
  kConnect,
  kEpollCtl,
  kClose,
  kSocket,
  kSocketNonBlockReuse,
  kMaxSyscall,
};

#define BATCHSYS_PACKED __attribute__((__packed__))

typedef struct accept_params {
  int sockfd;
  struct sockaddr* addr;
  uint32_t* addrlen;
} BATCHSYS_PACKED accept_params_t;

typedef struct accept4_params {
  int sockfd;
  struct sockaddr* addr;
  uint32_t* addrlen;
  int flags;
} BATCHSYS_PACKED accept4_params_t;

typedef struct read_params {
  int fd;
  void* buf;
  size_t count;
} BATCHSYS_PACKED read_params_t;

typedef struct pread_params {
  int fd;
  void* buf;
  size_t count;
  off_t offset;
} BATCHSYS_PACKED pread_params_t;

typedef struct readv_params {
  int fd;
  const struct iovec* iov;
  int iovcnt;
} BATCHSYS_PACKED readv_params_t;

typedef struct recv_params {
  int sockfd;
  void* buf;
  size_t len;
  int flags;
} BATCHSYS_PACKED recv_params_t;

typedef struct recvfrom_params {
  int sockfd;
  void* buf;
  size_t len;
  int flags;
  struct sockaddr* src_addr;
  uint32_t* addrlen;
} BATCHSYS_PACKED recvfrom_params_t;

typedef struct write_params {
  int fd;
  const void* buf;
  size_t count;
} BATCHSYS_PACKED write_params_t;

typedef struct pwrite_params {
  int fd;
  const void* buf;
  size_t count;
  off_t offset;
} BATCHSYS_PACKED pwrite_params_t;

typedef struct writev_params {
  int fd;
  const struct iovec* iov;
  int iovcnt;
} BATCHSYS_PACKED writev_params_t;

typedef struct send_params {
  int sockfd;
  const void* buf;
  size_t len;
  int flags;
} BATCHSYS_PACKED send_params_t;

typedef struct sendto_params {
  int sockfd;
  const void* buf;
  size_t len;
  int flags;
  const struct sockaddr* dest_addr;
  uint32_t addrlen;
} BATCHSYS_PACKED sendto_params_t;

typedef struct connect_params {
  int sockfd;
  const struct sockaddr* addr;
  uint32_t addrlen;
} BATCHSYS_PACKED connect_params_t;

typedef struct close_params {
  int fd;
} BATCHSYS_PACKED close_params_t;

typedef struct epoll_ctl_params {
  int epfd;
  int op;
  int fd;
  struct epoll_event event;
} BATCHSYS_PACKED epoll_ctl_params_t;

typedef struct socket_params {
  int domain;
  int type;
  int protocol;
} BATCHSYS_PACKED socket_params_t;

typedef struct syscall_params {
  uint8_t syscall;
  char params[];
} BATCHSYS_PACKED syscall_params_t;

typedef struct syscall_result {
  ssize_t result;
  int64_t error;
} BATCHSYS_PACKED syscall_result_t;

#define BATCHSYS_MAX_RESULTS (72)
#define BATCHSYS_MAX_PARAM_SIZE (40)
#define BATCHSYS_PARAM_SIZE (BATCHSYS_MAX_RESULTS * BATCHSYS_MAX_PARAM_SIZE)

typedef struct batchsys_incoming {
  uint64_t count;
  char bytes[BATCHSYS_PARAM_SIZE];
} BATCHSYS_PACKED batchsys_incoming_t;

BATCHSYS_STATIC_ASSERT(sizeof(batchsys_incoming_t) == 2888,
                       SizeCheckBatchSysIncoming);

#define BATCHSYS_CHECK_PARAM_SIZE(x)                           \
  BATCHSYS_STATIC_ASSERT(sizeof(x) <= BATCHSYS_MAX_PARAM_SIZE, \
                         ParamSizeCheck##x)

BATCHSYS_CHECK_PARAM_SIZE(accept_params_t);
BATCHSYS_CHECK_PARAM_SIZE(accept4_params_t);
BATCHSYS_CHECK_PARAM_SIZE(read_params_t);
BATCHSYS_CHECK_PARAM_SIZE(pread_params_t);
BATCHSYS_CHECK_PARAM_SIZE(readv_params_t);
BATCHSYS_CHECK_PARAM_SIZE(recv_params_t);
BATCHSYS_CHECK_PARAM_SIZE(recvfrom_params_t);
BATCHSYS_CHECK_PARAM_SIZE(write_params_t);
BATCHSYS_CHECK_PARAM_SIZE(pwrite_params_t);
BATCHSYS_CHECK_PARAM_SIZE(writev_params_t);
BATCHSYS_CHECK_PARAM_SIZE(send_params_t);
BATCHSYS_CHECK_PARAM_SIZE(sendto_params_t);
BATCHSYS_CHECK_PARAM_SIZE(connect_params_t);
BATCHSYS_CHECK_PARAM_SIZE(close_params_t);
BATCHSYS_CHECK_PARAM_SIZE(epoll_ctl_params_t);
BATCHSYS_CHECK_PARAM_SIZE(socket_params_t);
BATCHSYS_CHECK_PARAM_SIZE(syscall_params_t);
BATCHSYS_CHECK_PARAM_SIZE(syscall_result_t);

typedef struct batchsys_outgoing {
  uint64_t count;
  syscall_result_t results[BATCHSYS_MAX_RESULTS];
} BATCHSYS_PACKED batchsys_outgoing_t;

BATCHSYS_STATIC_ASSERT(sizeof(batchsys_outgoing_t) == 1160,
                       SizeCheckBatchSysIncoming);

typedef struct batchsys_process_params {
  batchsys_incoming_t incoming;
  batchsys_outgoing_t outgoing;
} BATCHSYS_PACKED batchsys_process_params_t;

BATCHSYS_STATIC_ASSERT(sizeof(batchsys_process_params_t) == 4048,
                       SizeCheckBatchSysIncoming);

typedef struct batchsys_batch {
  uint32_t id;
  uint32_t byte_count;
  batchsys_process_params_t params;
} batchsys_batch_t;

BATCHSYS_STATIC_ASSERT(sizeof(batchsys_batch_t) == 4056,
                       SizeCheckBatchSysBatch);

#define BATCHSYS_MAGIC (193)

#define BATCHSYS_OP_EXECUTE_BATCH (_IO(BATCHSYS_MAGIC, 1))
#define BATCHSYS_OP_CLOSE_FD (_IO(BATCHSYS_MAGIC, 2))
#define BATCHSYS_OP_SET_FILE_LIMIT (_IO(BATCHSYS_MAGIC, 3))
#define BATCHSYS_OP_CACHED_FDS (_IO(BATCHSYS_MAGIC, 4))

int batchsys_get_fd_limit(void);

int batchsys_open(void);

void batchsys_close(int batchsys_fd);

batchsys_batch_t* batchsys_batch_alloc(int batchsys_fd);

void batchsys_batch_free(batchsys_batch_t* batch);

static inline void batchsys_batch_reset(batchsys_batch_t* batch) {
  batch->byte_count = 0;
  batch->params.incoming.count = 0;
  batch->params.outgoing.count = 0;
}

static inline int batchsys_batch_full(const batchsys_batch_t* batch) {
  return batch->params.incoming.count >= BATCHSYS_MAX_RESULTS;
}

static inline int batchsys_batch_empty(const batchsys_batch_t* batch) {
  return batch->params.incoming.count == 0;
}

static inline uint64_t batch_batch_result_count(const batchsys_batch_t* batch) {
  return batch->params.outgoing.count;
}

static inline const syscall_result_t* batch_batch_get_result(
    const batchsys_batch_t* batch, uint64_t index) {
  return &batch->params.outgoing.results[index];
}

int batchsys_close_fd(int batchsys_fd, int fd);

// For debugging only, runs in O(n).
int batchsys_cached_fds(int batchsys_fd);

int batchsys_post_batch(int batchsys_fd, batchsys_batch_t* batch);

int batchsys_push_read(batchsys_batch_t* batch, int fd, void* buf,
                       size_t count);

int batchsys_push_pread(batchsys_batch_t* batch, int fd, void* buf,
                        size_t count, off_t offset);

int batchsys_push_readv(batchsys_batch_t* batch, int fd,
                        const struct iovec* iov, int iovcnt);

int batchsys_push_write(batchsys_batch_t* batch, int fd, const void* buf,
                        size_t count);

int batchsys_push_pwrite(batchsys_batch_t* batch, int fd, const void* buf,
                         size_t count, off_t offset);

int batchsys_push_writev(batchsys_batch_t* batch, int fd,
                         const struct iovec* iov, int iovcnt);

int batchsys_push_recv(batchsys_batch_t* batch, int sockfd, void* buf,
                       size_t len, int flags);

int batchsys_push_recvfrom(batchsys_batch_t* batch, int sockfd, void* buf,
                           size_t len, int flags, struct sockaddr* src_addr,
                           uint32_t* addrlen);

int batchsys_push_send(batchsys_batch_t* batch, int sockfd, const void* buf,
                       size_t len, int flags);

int batchsys_push_sendto(batchsys_batch_t* batch, int sockfd, const void* buf,
                         size_t len, int flags,
                         const struct sockaddr* dest_addr, uint32_t addrlen);

int batchsys_push_accept(batchsys_batch_t* batch, int sockfd,
                         struct sockaddr* addr, uint32_t* addrlen);

int batchsys_push_accept4(batchsys_batch_t* batch, int sockfd,
                          struct sockaddr* addr, uint32_t* addrlen, int flags);

// Pushes an 'accept4', plus batchsys will ensure the new socket is non-blocking
// and will set SO_REUSEADDR.
int batchsys_push_accept4_non_block_reuse(batchsys_batch_t* batch, int sockfd,
                                          struct sockaddr* addr,
                                          uint32_t* addrlen, int flags);

int batchsys_push_connect(batchsys_batch_t* batch, int sockfd,
                          const struct sockaddr* addr, uint32_t addrlen);

int batchsys_push_epoll_ctl(batchsys_batch_t* batch, int epfd, int op, int fd,
                            struct epoll_event* event);

int batchsys_push_close(batchsys_batch_t* batch, int fd);

int batchsys_push_socket(batchsys_batch_t* batch, int domain, int type,
                         int protocol);

// Pushes a 'socket' plus batchsys will ensure the new socket is non-blocking
// and will set SO_REUSEADDR.
int batchsys_push_socket_non_block_reuse(batchsys_batch_t* batch, int domain,
                                         int type, int protocol);

#ifdef __cplusplus
}
#endif

#endif  // BATCHSYS_H_
