// SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
// SPDX-License-Identifier: MIT

// Make intellisense happy.
#ifndef __KERNEL__
#define __KERNEL__
#define KBUILD_MODNAME "batchsys"
#define DKBUILD_BASENAME "batchsys"
#define __GENKSYMS__
#define CC_USING_FENTRY
#define MODULE
#define __KBUILD_MODNAME kmod_batchsys
#endif

#include "batchsys.h"

#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Watling (briankwatling@gmail.com)");
MODULE_DESCRIPTION("A module for system call batching");

enum State {
  kOk,
  kBadSyscall,
  kNullSyscall,
  kUnrecoverable,
};

#define MAX_BATCHES (256)

typedef struct batchsys_context {
  enum State state;
  int max_fd;
  atomic_t next_batch_id;
  batchsys_batch_t* batches[MAX_BATCHES];
  struct file** registered_files;
} batchsys_context_t;

static inline void context_uncache_filp(batchsys_context_t* context, int fd) {
  if (likely(fd >= 0 && fd < context->max_fd)) {
    struct file* filp = context->registered_files[fd];
    if (likely(filp)) {
      fput(filp);
      context->registered_files[fd] = NULL;
    }
  }
}

static struct file* context_get_filp(batchsys_context_t* context, int fd,
                                     struct file** filp_to_put) {
  struct file* filp;
  if (likely(fd >= 0 && fd < context->max_fd)) {
    filp = context->registered_files[fd];
    if (likely(filp)) {
      return filp;
    }
    filp = fget(fd);
    context->registered_files[fd] = filp;
    return filp;
  }
  filp = fget(fd);
  *filp_to_put = filp;
  return filp;
}

// A BatchSysCall returns the sizeof() the SyscallParams it used.
typedef int (*batchsys_syscall_t)(batchsys_context_t*, syscall_params_t*,
                                  syscall_result_t*);

static batchsys_syscall_t batchsys_syscalls[kMaxSyscall] = {};

#define BATCHSYS_SYSCALL_BEGIN(name, fd) \
  BATCHSYS_SYSCALL_BEGIN_INTERNAL(name, _, name##_params_t, fd)

#define BATCHSYS_SYSCALL_BEGIN_INTERNAL(name, name_prefix, paramtype, fd)    \
  static int batchsys##name_prefix##name(batchsys_context_t* context,        \
                                         syscall_params_t* syscall_params,   \
                                         syscall_result_t* result) {         \
    struct file* filp_to_put = NULL;                                         \
    paramtype* params = (paramtype*)(syscall_params + 1);                    \
    struct file* filp = context_get_filp(context, params->fd, &filp_to_put); \
    if (!filp) {                                                             \
      result->error = -EINVAL;                                               \
      result->result = -1;                                                   \
      return sizeof(*params);                                                \
    }                                                                        \
    result->error = 0;

#define BATCHSYS_SYSCALL_END   \
  goto done;                   \
  done:                        \
  if (unlikely(filp_to_put)) { \
    fput(filp_to_put);         \
  }                            \
  return sizeof(*params);      \
  }

BATCHSYS_SYSCALL_BEGIN(accept, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result = sys_accept(params->sockfd, params->addr,
  params->addrlen); if (result->result < 0) { result->error = -result->result;
    result->result = -1;
  } else {
    context_cache_filp(context, result->result);
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(accept4, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result =
      sys_accept4(params->sockfd, params->addr, params->addrlen,
  params->flags); if (result->result < 0) { result->error = -result->result;
    result->result = -1;
  } else {
    context_cache_filp(context, result->result);
  }*/
}
BATCHSYS_SYSCALL_END

/*static int set_reuse_addr(struct file* filp) {
  struct socket* sock = sock_from_file(filp);
  int on = 1;
  sockptr_t ptr = {.is_kernel = true, .kernel = &on};
  if (!sock) {
    return -EINVAL;
  }
  return sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, ptr, sizeof(on));
}*/

/*static int make_non_blocking_reuse(batchsys_context_t* context, int fd)
{ struct file* filp = context_cache_filp(context, fd); const int ret =
set_reuse_addr(filp); if (ret < 0) { context_uncache_filp(context, fd); return
ret;
  }
  spin_lock(&filp->f_lock);
  filp->f_flags |= O_NONBLOCK;
  spin_unlock(&filp->f_lock);
  return 0;
}*/

BATCHSYS_SYSCALL_BEGIN_INTERNAL(accept4, _non_block_reuse_, accept4_params_t,
                                sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*
  // Note that SOCK_NONBLOCK sets O_NONBLOCK for us.
  result->result = sys_accept4(params->sockfd, params->addr, params->addrlen,
                               params->flags | SOCK_NONBLOCK);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  } else {
    struct file* filp = context_cache_filp(context, result->result);
    const int ret = set_reuse_addr(filp);
    if (ret < 0) {
      context_uncache_filp(context, result->result);
      sys_close(result->result);
      result->result = -1;
      result->error = -ret;
    }
  }
  */
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(read, fd) {
  struct file* const filp = context_get_filp(context, params->fd, &filp_to_put);
  if (!filp) {
    result->error = -EINVAL;
    result->result = -1;
    goto done;
  }
  result->result = kernel_read(filp, params->buf, params->count, &filp->f_pos);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(pread, fd) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result =
      ksys_pread64(params->fd, params->buf, params->count, params->offset);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(readv, fd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO: use vfs_iter_read and import_iovec
  result->result = sys_readv(params->fd, params->iov, params->iovcnt);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(recv, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  // TODO(bwatling): use sock_recvmsg?
  result->result =
      sys_recv(params->sockfd, params->buf, params->len, params->flags);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(recvfrom, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  // TODO(bwatling): use sock_recvmsg?
  result->result =
      sys_recvfrom(params->sockfd, params->buf, params->len, params->flags,
                   params->src_addr, params->addrlen);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(write, fd) {
  struct file* filp = context_get_filp(context, params->fd, &filp_to_put);
  if (!filp) {
    result->error = -EINVAL;
    result->result = -1;
    goto done;
  }
  result->result = kernel_write(filp, params->buf, params->count, &filp->f_pos);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(pwrite, fd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  result->result =
      sys_pwrite64(params->fd, params->buf, params->count, params->offset);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(writev, fd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  result->result = sys_writev(params->fd, params->iov, params->iovcnt);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(send, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  // TODO(bwatling): use sock_sendmsg?
  result->result =
      sys_send(params->sockfd, (void*)params->buf, params->len,
  params->flags); if (result->result < 0) { result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(sendto, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*// TODO(bwatling): use cached filp?
  // TODO(bwatling): use sock_sendmsg?
  result->result =
      sys_sendto(params->sockfd, (void*)params->buf, params->len,
  params->flags, (struct sockaddr*)params->dest_addr, params->addrlen); if
  (result->result < 0) { result->error = -result->result; result->result =
  -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(connect, sockfd) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result = sys_connect(params->sockfd, (struct
  sockaddr*)params->addr, params->addrlen); if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  } else {
    context_cache_filp(context, result->result);
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(epoll_ctl, epfd) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result =
      sys_epoll_ctl(params->epfd, params->op, params->fd, &params->event);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN_INTERNAL(close_, _, close_params_t, fd) {
  context_uncache_filp(context, params->fd);
  result->result = close_fd(params->fd);
  if (result->result < 0) {
    result->error = -result->result;
    result->result = -1;
  }
}
BATCHSYS_SYSCALL_END

static int batchsys_socket(batchsys_context_t* context,
                           syscall_params_t* syscall_params,
                           syscall_result_t* result) {
  socket_params_t* params = (socket_params_t*)(syscall_params + 1);
  result->error = ENODEV;
  result->result = -1;
  return sizeof(*params);
}

static int batchsys_non_block_reuse_socket(batchsys_context_t* context,
                                           syscall_params_t* syscall_params,
                                           syscall_result_t* result) {
  socket_params_t* params = (socket_params_t*)(syscall_params + 1);
  result->error = ENODEV;
  result->result = -1;
  return sizeof(*params);
}

static int batchsys_process(batchsys_context_t* context,
                            batchsys_batch_t* batch) {
  char* spot = NULL;
  char* end = NULL;
  int ret;
  uint32_t i;
  batchsys_process_params_t* params = &batch->params;
  batchsys_syscall_t syscall = NULL;
  syscall_params_t* syscall_params = NULL;

  if (context->state != kOk) {
    printk(KERN_WARNING "batchsys_process bad state: %d\n", context->state);
    return -EFAULT;
  }

  if (!params) {
    printk(KERN_WARNING "batchsys_process null user_params\n");
    return -EFAULT;
  }
  if (params->incoming.count > BATCHSYS_MAX_RESULTS) {
    printk(KERN_WARNING "batchsys_process too many syscalls %llu\n",
           params->incoming.count);
    return -EFAULT;
  }
  spot = params->incoming.bytes;
  end = spot + sizeof(params->incoming.bytes);
  params->outgoing.count = 0;
  for (i = 0; i < params->incoming.count && spot < end; ++i) {
    // TODO(bwatling): detect when userspace has too many requests in
    // 'bytes'? Currently it's possible to read into the results array.

    syscall_params = (syscall_params_t*)spot;
    if (syscall_params->syscall >= kMaxSyscall) {
      printk(KERN_ERR "batchsys invalid syscall: %u\n",
             syscall_params->syscall);
      context->state = kBadSyscall;
      return -EINVAL;
    }
    syscall = batchsys_syscalls[syscall_params->syscall];
    if (!syscall) {
      printk(KERN_ERR "batchsys null syscall\n");
      context->state = kNullSyscall;
      return -EINVAL;
    }

    ret = syscall(context, syscall_params,
                  &params->outgoing.results[params->outgoing.count]);
    ++params->outgoing.count;
    if (ret > 0) {
      // The syscall completed. 'ret' is sizeof(*syscall_params).
      spot += ret + sizeof(syscall_params_t);
    } else {
      printk(KERN_ERR "batchsys unrecoverable error: %d\n", ret);
      context->state = kUnrecoverable;
      return -EINVAL;
    }
  }

  return params->incoming.count;
}

static long batchsys_set_file_cache_size(batchsys_context_t* context,
                                         unsigned int count) {
  size_t total_size = sizeof(context->registered_files[0]) * count;
  if (count > INT_MAX) {
    return -EINVAL;
  }
  if (context->registered_files) {
    return -EINVAL;
  }
  context->registered_files = vmalloc(total_size);
  if (!context->registered_files) {
    printk(KERN_ERR "batchsys could not allocate cache for max_fd = %d\n",
           (int)count);
    return -ENOMEM;
  }
  memset(context->registered_files, 0, total_size);
  context->max_fd = (int)count;
  printk(KERN_INFO "batchsys set max_fd = %d\n", context->max_fd);
  return 0;
}

static long batchsys_ioctl(struct file* filp, unsigned int op,
                           unsigned long arg) {
  batchsys_context_t* context = filp->private_data;
  switch (op) {
    case BATCHSYS_OP_EXECUTE_BATCH:
      batchsys_batch_t* batch;
      if (arg > MAX_BATCHES) {
        printk(KERN_ERR "batchsys index > MAX_BATCHES\n");
        return -EINVAL;
      }
      if (arg >= atomic_read(&context->next_batch_id)) {
        printk(KERN_ERR "batchsys index too high\n");
        return -EINVAL;
      }
      batch = context->batches[arg];
      if (!batch) {
        printk(KERN_ERR "batchsys no batch\n");
        return -EINVAL;
      }
      return batchsys_process(context, batch);
    case BATCHSYS_OP_CLOSE_FD:
      context_uncache_filp(context, arg);
      return close_fd(arg);
    case BATCHSYS_OP_SET_FILE_LIMIT:
      return batchsys_set_file_cache_size(context, arg);
    case BATCHSYS_OP_CACHED_FDS:
      int count = 0;
      int i;
      for (i = 0; i < context->max_fd; ++i) {
        if (context->registered_files[i]) {
          count++;
        }
      }
      return count;
  }
  return -EINVAL;
}

static int batchsys_module_open(struct inode* inode, struct file* filp) {
  batchsys_context_t* context;
  filp->f_flags |= O_CLOEXEC;
  context = kmalloc(sizeof(*context), GFP_KERNEL);
  if (!context) {
    return -ENOMEM;
  }
  memset(context, 0, sizeof(*context));
  context->state = kOk;
  filp->private_data = context;
  printk(KERN_INFO "batchsys opened\n");
  return 0;
}

static int batchsys_module_close(struct inode* inode, struct file* filp) {
  batchsys_context_t* context = filp->private_data;
  if (context) {
    int count = 0;
    int i;
    for (i = 0; i < context->max_fd; ++i) {
      if (context->registered_files[i]) {
        ++count;
        fput(context->registered_files[i]);
      }
    }
    if (count) {
      printk(KERN_INFO
             "batchsys leaked fds (pointers, not ref counted fds): %d\n",
             count);
    }
  }
  if (context->registered_files) {
    vfree(context->registered_files);
  }
  kfree(context);
  printk(KERN_INFO "batchsys closed\n");
  return 0;
}

static void mmap_close(struct vm_area_struct* vma) {
  batchsys_batch_t* batch = vma->vm_private_data;
  printk(KERN_INFO "batchsys free batch %d\n", batch->id);
  free_page((long unsigned int)batch);
}

static struct vm_operations_struct mmap_ops = {
    .close = mmap_close,
};

static int batchsys_mmap(struct file* filp, struct vm_area_struct* vma) {
  batchsys_batch_t* batch;
  batchsys_context_t* context = filp->private_data;
  const int spot = atomic_add_return(1, &context->next_batch_id) - 1;
  if (spot >= MAX_BATCHES) {
    printk(KERN_ERR "batchsys too many batches\n");
    return -EINVAL;
  }
  vma->vm_ops = &mmap_ops;
  if (sizeof(batchsys_batch_t) > PAGE_SIZE) {
    printk(KERN_ERR "batchsys sizeof(batchsys_batch_t) > PAGE_SIZE\n");
    return -EINVAL;
  }
  batch = (batchsys_batch_t*)__get_free_page(GFP_KERNEL);
  if (!batch) {
    printk(KERN_ERR "batchsys could not allocate page for batch\n");
    return -ENOMEM;
  }
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
  vma->vm_flags |= VM_RESERVED;
#else
  vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#endif
  vma->vm_private_data = batch;
  if (remap_pfn_range(vma, vma->vm_start, virt_to_phys(batch) >> PAGE_SHIFT,
                      sizeof(batchsys_batch_t), PAGE_SHARED)) {
    kfree(batch);
    printk(KERN_ERR "batchsys mmap remap_pfn_range failed\n");
    return -EIO;
  }
  batch->id = spot;
  context->batches[spot] = batch;
  printk(KERN_INFO "batchsys registered batch %d\n", spot);
  return 0;
}

static struct file_operations batchsys_operations = {
    .owner = THIS_MODULE,
    .open = batchsys_module_open,
    .release = batchsys_module_close,
    .unlocked_ioctl = batchsys_ioctl,
    .compat_ioctl = batchsys_ioctl,
    .mmap = batchsys_mmap,
};

static struct miscdevice batchsys_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "batchsys",
    .fops = &batchsys_operations,
    .mode = S_IRUGO | S_IWUGO,
};

int init_module(void) {
  int ret;

  batchsys_syscalls[kAccept] = &batchsys_accept;
  batchsys_syscalls[kAccept4] = &batchsys_accept4;
  batchsys_syscalls[kAccept4NonBlockReuse] = &batchsys_non_block_reuse_accept4;
  batchsys_syscalls[kRead] = &batchsys_read;
  batchsys_syscalls[kPread] = &batchsys_pread;
  batchsys_syscalls[kReadv] = &batchsys_readv;
  batchsys_syscalls[kRecv] = &batchsys_recv;
  batchsys_syscalls[kRecvfrom] = &batchsys_recvfrom;
  batchsys_syscalls[kWrite] = &batchsys_write;
  batchsys_syscalls[kPwrite] = &batchsys_pwrite;
  batchsys_syscalls[kWritev] = &batchsys_writev;
  batchsys_syscalls[kSend] = &batchsys_send;
  batchsys_syscalls[kSendto] = &batchsys_sendto;
  batchsys_syscalls[kConnect] = &batchsys_connect;
  batchsys_syscalls[kEpollCtl] = &batchsys_epoll_ctl;
  batchsys_syscalls[kClose] = &batchsys_close_;
  batchsys_syscalls[kSocket] = &batchsys_socket;
  batchsys_syscalls[kSocketNonBlockReuse] = &batchsys_non_block_reuse_socket;

  ret = misc_register(&batchsys_device);
  if (ret < 0) {
    printk(KERN_ERR "batchsys registration failed: %d\n", ret);
    return ret;
  }

  printk(KERN_INFO "batchsys loaded\n");
  printk(KERN_INFO "sizeof(SyscallParams) = %d\n",
         (int)sizeof(syscall_params_t));
  printk(KERN_INFO "sizeof(BatchSysProcessParams) = %d\n",
         (int)sizeof(batchsys_process_params_t));
  return 0;
}

void cleanup_module(void) {
  misc_deregister(&batchsys_device);
  printk(KERN_INFO "batchsys unloaded\n");
}
