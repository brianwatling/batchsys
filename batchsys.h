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

#ifdef __GNUC__
#define BATCHSYS_STATIC_ASSERT_HELPER(expr, msg)                     \
  (!!sizeof(struct {                                                 \
    unsigned int BATCHSYS_STATIC_ASSERTION__##msg : (expr) ? 1 : -1; \
  }))
#define BATCHSYS_STATIC_ASSERT(expr, msg) \
  extern int(                             \
      *_assert_function__(void))[BATCHSYS_STATIC_ASSERT_HELPER(expr, msg)]
#else
#define BATCHSYS_STATIC_ASSERT(expr, msg)          \
  extern char BATCHSYS_STATIC_ASSERTION__##msg[1]; \
  extern char BATCHSYS_STATIC_ASSERTION__##msg[(expr) ? 1 : 2]
#endif /* #ifdef __GNUC__ */

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

struct SocketpairParams {
  int domain;
  int type;
  int protocol;
  int* sv;
} BATCHSYS_PACKED;

struct AcceptParams {
  int sockfd;
  struct sockaddr* addr;
  uint32_t* addrlen;
} BATCHSYS_PACKED;

struct Accept4Params {
  int sockfd;
  struct sockaddr* addr;
  uint32_t* addrlen;
  int flags;
} BATCHSYS_PACKED;

struct ReadParams {
  int fd;
  void* buf;
  size_t count;
} BATCHSYS_PACKED;

struct PreadParams {
  int fd;
  void* buf;
  size_t count;
  off_t offset;
} BATCHSYS_PACKED;

struct ReadvParams {
  int fd;
  const struct iovec* iov;
  int iovcnt;
} BATCHSYS_PACKED;

struct RecvParams {
  int sockfd;
  void* buf;
  size_t len;
  int flags;
} BATCHSYS_PACKED;

struct RecvfromParams {
  int sockfd;
  void* buf;
  size_t len;
  int flags;
  struct sockaddr* src_addr;
  uint32_t* addrlen;
} BATCHSYS_PACKED;

struct WriteParams {
  int fd;
  const void* buf;
  size_t count;
};

struct PwriteParams {
  int fd;
  const void* buf;
  size_t count;
  off_t offset;
};

struct WritevParams {
  int fd;
  const struct iovec* iov;
  int iovcnt;
} BATCHSYS_PACKED;

struct SendParams {
  int sockfd;
  const void* buf;
  size_t len;
  int flags;
} BATCHSYS_PACKED;

struct SendtoParams {
  int sockfd;
  const void* buf;
  size_t len;
  int flags;
  const struct sockaddr* dest_addr;
  uint32_t addrlen;
} BATCHSYS_PACKED;

struct ConnectParams {
  int sockfd;
  const struct sockaddr* addr;
  uint32_t addrlen;
} BATCHSYS_PACKED;

struct PipeParams {
  int* pipefd;
} BATCHSYS_PACKED;

struct CloseParams {
  int fd;
} BATCHSYS_PACKED;

struct EpollCtlParams {
  int epfd;
  int op;
  int fd;
  struct epoll_event event;
} BATCHSYS_PACKED;

struct CloseFdParams {
  int fd;
} BATCHSYS_PACKED;

struct SocketParams {
  int domain;
  int type;
  int protocol;
} BATCHSYS_PACKED;

struct SyscallParams {
  uint8_t syscall;
  char params[];
} BATCHSYS_PACKED;

struct SyscallResult {
  ssize_t result;
  int64_t error;
} BATCHSYS_PACKED;

#define BATCHSYS_MAX_RESULTS (72)
#define BATCHSYS_MAX_PARAM_SIZE (40)
#define BATCHSYS_PARAM_SIZE (BATCHSYS_MAX_RESULTS * BATCHSYS_MAX_PARAM_SIZE)

struct BatchSysIncoming {
  uint64_t count;
  char bytes[BATCHSYS_PARAM_SIZE];
} BATCHSYS_PACKED;

BATCHSYS_STATIC_ASSERT(sizeof(struct BatchSysIncoming) == 2888,
                       SizeCheckBatchSysIncoming);

#define BATCHSYS_CHECK_PARAM_SIZE(x)                                  \
  BATCHSYS_STATIC_ASSERT(sizeof(struct x) <= BATCHSYS_MAX_PARAM_SIZE, \
                         ParamSizeCheck##x)

BATCHSYS_CHECK_PARAM_SIZE(SocketpairParams);
BATCHSYS_CHECK_PARAM_SIZE(AcceptParams);
BATCHSYS_CHECK_PARAM_SIZE(Accept4Params);
BATCHSYS_CHECK_PARAM_SIZE(ReadParams);
BATCHSYS_CHECK_PARAM_SIZE(PreadParams);
BATCHSYS_CHECK_PARAM_SIZE(ReadvParams);
BATCHSYS_CHECK_PARAM_SIZE(RecvParams);
BATCHSYS_CHECK_PARAM_SIZE(RecvfromParams);
BATCHSYS_CHECK_PARAM_SIZE(WriteParams);
BATCHSYS_CHECK_PARAM_SIZE(PwriteParams);
BATCHSYS_CHECK_PARAM_SIZE(WritevParams);
BATCHSYS_CHECK_PARAM_SIZE(SendParams);
BATCHSYS_CHECK_PARAM_SIZE(SendtoParams);
BATCHSYS_CHECK_PARAM_SIZE(ConnectParams);
BATCHSYS_CHECK_PARAM_SIZE(PipeParams);
BATCHSYS_CHECK_PARAM_SIZE(CloseParams);
BATCHSYS_CHECK_PARAM_SIZE(EpollCtlParams);
BATCHSYS_CHECK_PARAM_SIZE(CloseFdParams);
BATCHSYS_CHECK_PARAM_SIZE(SocketParams);
BATCHSYS_CHECK_PARAM_SIZE(SyscallParams);
BATCHSYS_CHECK_PARAM_SIZE(SyscallResult);

struct BatchSysOutgoing {
  uint64_t count;
  struct SyscallResult results[BATCHSYS_MAX_RESULTS];
} BATCHSYS_PACKED;

BATCHSYS_STATIC_ASSERT(sizeof(struct BatchSysOutgoing) == 1160,
                       SizeCheckBatchSysIncoming);

struct BatchSysProcessParams {
  struct BatchSysIncoming incoming;
  struct BatchSysOutgoing outgoing;
} BATCHSYS_PACKED;

BATCHSYS_STATIC_ASSERT(sizeof(struct BatchSysProcessParams) == 4048,
                       SizeCheckBatchSysIncoming);

struct BatchSysBatch {
  uint32_t id;
  uint32_t byte_count;
  struct BatchSysProcessParams params;
};

#ifdef __cplusplus
extern "C" {
#endif

#define BATCHSYS_MAGIC (193)

#define BATCHSYS_OP_EXECUTE_BATCH (_IO(BATCHSYS_MAGIC, 1))
#define BATCHSYS_OP_CLOSE_FD (_IO(BATCHSYS_MAGIC, 2))
#define BATCHSYS_OP_SET_FILE_LIMIT (_IO(BATCHSYS_MAGIC, 3))

int batchsys_get_fd_limit(void);

int batchsys_open(void);

void batchsys_close(int batchsys_fd);

struct BatchSysBatch* batchsys_batch_alloc(int batchsys_fd);

void batchsys_batch_free(struct BatchSysBatch* batch);

static inline void batchsys_batch_reset(struct BatchSysBatch* batch) {
  batch->byte_count = 0;
  batch->params.incoming.count = 0;
  batch->params.outgoing.count = 0;
}

static inline int batchsys_batch_full(const struct BatchSysBatch* batch) {
  // TODO: check byte size remaining?
  return batch->params.incoming.count >= BATCHSYS_MAX_RESULTS;
}

static inline int batchsys_batch_empty(const struct BatchSysBatch* batch) {
  return batch->params.incoming.count == 0;
}

static inline uint64_t batch_batch_result_count(
    const struct BatchSysBatch* batch) {
  return batch->params.outgoing.count;
}

static inline const struct SyscallResult* batch_batch_get_result(
    const struct BatchSysBatch* batch, uint64_t index) {
  return &batch->params.outgoing.results[index];
}

int batchsys_close_fd(int batchsys_fd, int fd);

int batchsys_post_batch(int batchsys_fd, struct BatchSysBatch* batch);

int batchsys_push_read(struct BatchSysBatch* batch, int fd, void* buf,
                       size_t count);

int batchsys_push_pread(struct BatchSysBatch* batch, int fd, void* buf,
                        size_t count, off_t offset);

int batchsys_push_readv(struct BatchSysBatch* batch, int fd,
                        const struct iovec* iov, int iovcnt);

int batchsys_push_write(struct BatchSysBatch* batch, int fd, const void* buf,
                        size_t count);

int batchsys_push_pwrite(struct BatchSysBatch* batch, int fd, const void* buf,
                         size_t count, off_t offset);

int batchsys_push_writev(struct BatchSysBatch* batch, int fd,
                         const struct iovec* iov, int iovcnt);

int batchsys_push_recv(struct BatchSysBatch* batch, int sockfd, void* buf,
                       size_t len, int flags);

int batchsys_push_recvfrom(struct BatchSysBatch* batch, int sockfd, void* buf,
                           size_t len, int flags, struct sockaddr* src_addr,
                           uint32_t* addrlen);

int batchsys_push_send(struct BatchSysBatch* batch, int sockfd, const void* buf,
                       size_t len, int flags);

int batchsys_push_sendto(struct BatchSysBatch* batch, int sockfd,
                         const void* buf, size_t len, int flags,
                         const struct sockaddr* dest_addr, uint32_t addrlen);

int batchsys_push_accept(struct BatchSysBatch* batch, int sockfd,
                         struct sockaddr* addr, uint32_t* addrlen);

int batchsys_push_accept4(struct BatchSysBatch* batch, int sockfd,
                          struct sockaddr* addr, uint32_t* addrlen, int flags);

// Pushes an 'accept4', plus batchsys will ensure the new socket is non-blocking
// and will set SO_REUSEADDR.
int batchsys_push_accept4_non_block_reuse(struct BatchSysBatch* batch,
                                          int sockfd, struct sockaddr* addr,
                                          uint32_t* addrlen, int flags);

int batchsys_push_connect(struct BatchSysBatch* batch, int sockfd,
                          const struct sockaddr* addr, uint32_t addrlen);

int batchsys_push_epoll_ctl(struct BatchSysBatch* batch, int epfd, int op,
                            int fd, struct epoll_event* event);

int batchsys_push_close(struct BatchSysBatch* batch, int fd);

int batchsys_push_socket(struct BatchSysBatch* batch, int domain, int type,
                         int protocol);

// Pushes a 'socket' plus batchsys will ensure the new socket is non-blocking
// and will set SO_REUSEADDR.
int batchsys_push_socket_non_block_reuse(struct BatchSysBatch* batch,
                                         int domain, int type, int protocol);

#ifdef __cplusplus
}
#endif

#endif  // BATCHSYS_H_
