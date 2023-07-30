// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "batchsys.h"

int batchsys_get_fd_limit(void) {
  struct rlimit rlim;
  if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    return -1;
  }
  return rlim.rlim_max;
}

typedef int (*IoctlFunction)(int d, int request, ...);
static IoctlFunction real_ioctl = 0;
typedef int (*OpenFunction)(const char*, int, ...);
static OpenFunction real_open = 0;
typedef int (*CloseFunction)(int fd);
static CloseFunction real_close = 0;
typedef void* (*MmapFunction)(void*, size_t, int, int, int, off_t);
static MmapFunction real_mmap = 0;
typedef int (*MunmapFunction)(void*, size_t);
static MunmapFunction real_munmap = 0;

#define GET_REAL_FUNCTION(type, name)              \
  do {                                             \
    if (!real_##name) {                            \
      real_##name = (type)dlsym(RTLD_NEXT, #name); \
      if (!real_##name) {                          \
        real_##name = (type)&name;                 \
      }                                            \
    }                                              \
  } while (0)

int batchsys_open() {
  GET_REAL_FUNCTION(IoctlFunction, ioctl);
  GET_REAL_FUNCTION(OpenFunction, open);
  GET_REAL_FUNCTION(CloseFunction, close);
  GET_REAL_FUNCTION(MmapFunction, mmap);
  GET_REAL_FUNCTION(MunmapFunction, munmap);

  int fd = real_open("/dev/batchsys", O_RDONLY);
  if (fd < 0) {
    return fd;
  }
  if (ioctl(fd, BATCHSYS_OP_SET_FILE_LIMIT, batchsys_get_fd_limit()) < 0) {
    batchsys_close(fd);
    return -1;
  }
  return fd;
}

void batchsys_close(int batchsys_fd) { real_close(batchsys_fd); }

batchsys_batch_t* batchsys_batch_alloc(int batchsys_fd) {
  batchsys_batch_t* ret =
      real_mmap(0, sizeof(batchsys_batch_t), PROT_READ | PROT_WRITE,
                MAP_PRIVATE, batchsys_fd, 0);
  if (ret == MAP_FAILED) {
    return 0;
  }
  batchsys_batch_reset(ret);
  return ret;
}

void batchsys_batch_free(batchsys_batch_t* batch) {
  if (batch) {
    real_munmap(batch, sizeof(*batch));
  }
}

int batchsys_close_fd(int batchsys_fd, int fd) {
  assert(real_ioctl);

  const int ret = real_ioctl(batchsys_fd, BATCHSYS_OP_CLOSE_FD, fd);
  return ret;
}

int batchsys_post_batch(int batchsys_fd, batchsys_batch_t* batch) {
  assert(batch);
  assert(real_ioctl);

  if (!batch->params.incoming.count) {
    return 0;
  }

  batch->byte_count += sizeof(batch->params.incoming.count);

  const int ret = real_ioctl(batchsys_fd, BATCHSYS_OP_EXECUTE_BATCH, batch->id);
  return ret;
}

#define BATCHSYS_USER_PREAMBLE(call_number, param_type)           \
  syscall_params_t* params;                                       \
  param_type* call_params;                                        \
  const uint32_t new_byte_count =                                 \
      batch->byte_count + sizeof(*params) + sizeof(*call_params); \
  do {                                                            \
    char* dest;                                                   \
    if (new_byte_count > sizeof(batch->params.incoming) ||        \
        batch->params.incoming.count >= BATCHSYS_MAX_RESULTS) {   \
      return 0;                                                   \
    }                                                             \
    dest = batch->params.incoming.bytes + batch->byte_count;      \
    params = (syscall_params_t*)dest;                             \
    params->syscall = call_number;                                \
    call_params = (param_type*)(dest + sizeof(*params));          \
  } while (0)

#define BATCHSYS_USER_EPILOGUE          \
  do {                                  \
    batch->byte_count = new_byte_count; \
    batch->params.incoming.count += 1;  \
    return 1;                           \
  } while (0)

int batchsys_push_read(batchsys_batch_t* batch, int fd, void* buf,
                       size_t count) {
  BATCHSYS_USER_PREAMBLE(kRead, read_params_t);

  call_params->fd = fd;
  call_params->buf = buf;
  call_params->count = count;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_pread(batchsys_batch_t* batch, int fd, void* buf,
                        size_t count, off_t offset) {
  BATCHSYS_USER_PREAMBLE(kPread, pread_params_t);

  call_params->fd = fd;
  call_params->buf = buf;
  call_params->count = count;
  call_params->offset = offset;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_readv(batchsys_batch_t* batch, int fd,
                        const struct iovec* iov, int iovcnt) {
  BATCHSYS_USER_PREAMBLE(kReadv, readv_params_t);

  call_params->fd = fd;
  call_params->iov = iov;
  call_params->iovcnt = iovcnt;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_write(batchsys_batch_t* batch, int fd, const void* buf,
                        size_t count) {
  BATCHSYS_USER_PREAMBLE(kWrite, write_params_t);

  call_params->fd = fd;
  call_params->buf = buf;
  call_params->count = count;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_pwrite(batchsys_batch_t* batch, int fd, const void* buf,
                         size_t count, off_t offset) {
  BATCHSYS_USER_PREAMBLE(kPwrite, pwrite_params_t);

  call_params->fd = fd;
  call_params->buf = buf;
  call_params->count = count;
  call_params->offset = offset;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_writev(batchsys_batch_t* batch, int fd,
                         const struct iovec* iov, int iovcnt) {
  BATCHSYS_USER_PREAMBLE(kWritev, writev_params_t);

  call_params->fd = fd;
  call_params->iov = iov;
  call_params->iovcnt = iovcnt;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_recv(batchsys_batch_t* batch, int sockfd, void* buf,
                       size_t len, int flags) {
  BATCHSYS_USER_PREAMBLE(kRecv, recv_params_t);

  call_params->sockfd = sockfd;
  call_params->buf = buf;
  call_params->len = len;
  call_params->flags = flags;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_recvfrom(batchsys_batch_t* batch, int sockfd, void* buf,
                           size_t len, int flags, struct sockaddr* src_addr,
                           uint32_t* addrlen) {
  BATCHSYS_USER_PREAMBLE(kRecvfrom, recvfrom_params_t);

  call_params->sockfd = sockfd;
  call_params->buf = buf;
  call_params->len = len;
  call_params->flags = flags;
  call_params->src_addr = src_addr;
  call_params->addrlen = addrlen;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_send(batchsys_batch_t* batch, int sockfd, const void* buf,
                       size_t len, int flags) {
  BATCHSYS_USER_PREAMBLE(kSend, send_params_t);

  call_params->sockfd = sockfd;
  call_params->buf = buf;
  call_params->len = len;
  call_params->flags = flags;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_sendto(batchsys_batch_t* batch, int sockfd, const void* buf,
                         size_t len, int flags,
                         const struct sockaddr* dest_addr, uint32_t addrlen) {
  BATCHSYS_USER_PREAMBLE(kSendto, sendto_params_t);

  call_params->sockfd = sockfd;
  call_params->buf = buf;
  call_params->len = len;
  call_params->flags = flags;
  call_params->dest_addr = dest_addr;
  call_params->addrlen = addrlen;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_accept(batchsys_batch_t* batch, int sockfd,
                         struct sockaddr* addr, uint32_t* addrlen) {
  BATCHSYS_USER_PREAMBLE(kAccept, accept_params_t);

  call_params->sockfd = sockfd;
  call_params->addr = addr;
  call_params->addrlen = addrlen;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_accept4(batchsys_batch_t* batch, int sockfd,
                          struct sockaddr* addr, uint32_t* addrlen, int flags) {
  BATCHSYS_USER_PREAMBLE(kAccept4, accept4_params_t);

  call_params->sockfd = sockfd;
  call_params->addr = addr;
  call_params->addrlen = addrlen;
  call_params->flags = flags;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_accept4_non_block_reuse(batchsys_batch_t* batch, int sockfd,
                                          struct sockaddr* addr,
                                          uint32_t* addrlen, int flags) {
  BATCHSYS_USER_PREAMBLE(kAccept4NonBlockReuse, accept4_params_t);

  call_params->sockfd = sockfd;
  call_params->addr = addr;
  call_params->addrlen = addrlen;
  call_params->flags = flags;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_connect(batchsys_batch_t* batch, int sockfd,
                          const struct sockaddr* addr, uint32_t addrlen) {
  BATCHSYS_USER_PREAMBLE(kConnect, connect_params_t);

  call_params->sockfd = sockfd;
  call_params->addr = addr;
  call_params->addrlen = addrlen;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_epoll_ctl(batchsys_batch_t* batch, int epfd, int op, int fd,
                            struct epoll_event* event) {
  BATCHSYS_USER_PREAMBLE(kEpollCtl, epoll_ctl_params_t);

  call_params->epfd = epfd;
  call_params->op = op;
  call_params->fd = fd;
  call_params->event = *event;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_close(batchsys_batch_t* batch, int fd) {
  BATCHSYS_USER_PREAMBLE(kClose, close_params_t);

  call_params->fd = fd;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_socket(batchsys_batch_t* batch, int domain, int type,
                         int protocol) {
  BATCHSYS_USER_PREAMBLE(kSocket, socket_params_t);

  call_params->domain = domain;
  call_params->type = type;
  call_params->protocol = protocol;

  BATCHSYS_USER_EPILOGUE;
}

int batchsys_push_socket_non_block_reuse(batchsys_batch_t* batch, int domain,
                                         int type, int protocol) {
  BATCHSYS_USER_PREAMBLE(kSocketNonBlockReuse, socket_params_t);

  call_params->domain = domain;
  call_params->type = type;
  call_params->protocol = protocol;

  BATCHSYS_USER_EPILOGUE;
}
