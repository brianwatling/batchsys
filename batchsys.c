#include "batchsys.h"

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
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

struct BatchSysContext {
  enum State state;
  int max_fd;
  atomic_t next_batch_id;
  struct BatchSysBatch* batches[MAX_BATCHES];
  struct file** registered_files;
};

static struct file* context_cache_filp(struct BatchSysContext* context,
                                       int fd) {
  struct file* filp = fget(fd);
  if (likely(fd < context->max_fd)) {
    context->registered_files[fd] = filp;
  }
  fput(filp);
  // WARNING: This is dangerous. The file can be closed without us knowing. Make
  // sure to close files used with batchsys *through* batchsys. At the very
  // least don't use file descriptors which have been closed.
  return filp;
}

static inline void context_uncache_filp(struct BatchSysContext* context,
                                        int fd) {
  if (likely(fd < context->max_fd)) {
    context->registered_files[fd] = 0;
  }
}

static struct file* get_cached_filp(struct BatchSysContext* context, int fd) {
  if (unlikely(fd < 0)) {
    return NULL;
  }
  if (fd < context->max_fd && context->registered_files[fd]) {
    return context->registered_files[fd];
  }
  return context_cache_filp(context, fd);
}

// A BatchSysCall returns the sizeof() the SyscallParams it used.
typedef int (*BatchSysCall)(struct BatchSysContext*, struct SyscallParams*,
                            struct SyscallResult*);

static BatchSysCall batchsys_syscalls[kMaxSyscall] = {};

#define BATCHSYS_SYSCALL_BEGIN(name, paramtype) \
  BATCHSYS_SYSCALL_BEGIN_INTERNAL(name, _, paramtype)

#define BATCHSYS_SYSCALL_BEGIN_INTERNAL(name, name_prefix, paramtype)          \
  static int batchsys##name_prefix##name(struct BatchSysContext* context,      \
                                         struct SyscallParams* syscall_params, \
                                         struct SyscallResult* result) {       \
    struct paramtype* params = (struct paramtype*)(syscall_params + 1);        \
    result->error = 0;

#define BATCHSYS_SYSCALL_END \
  return sizeof(*params);    \
  }

BATCHSYS_SYSCALL_BEGIN(accept, AcceptParams) {
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

BATCHSYS_SYSCALL_BEGIN(accept4, Accept4Params) {
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

/*static int make_non_blocking_reuse(struct BatchSysContext* context, int fd)
{ struct file* filp = context_cache_filp(context, fd); const int ret =
set_reuse_addr(filp); if (ret < 0) { context_uncache_filp(context, fd); return
ret;
  }
  spin_lock(&filp->f_lock);
  filp->f_flags |= O_NONBLOCK;
  spin_unlock(&filp->f_lock);
  return 0;
}*/

BATCHSYS_SYSCALL_BEGIN_INTERNAL(accept4, _non_block_reuse_, Accept4Params) {
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

BATCHSYS_SYSCALL_BEGIN(read, ReadParams) {
  struct file* const filp = get_cached_filp(context, params->fd);
  if (!filp) {
    result->error = -EINVAL;
    result->result = -1;
  } else {
    result->result =
        kernel_read(filp, params->buf, params->count, &filp->f_pos);
    if (result->result < 0) {
      result->error = -result->result;
      result->result = -1;
    }
  }
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(pread, PreadParams) {
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

BATCHSYS_SYSCALL_BEGIN(readv, ReadvParams) {
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

BATCHSYS_SYSCALL_BEGIN(recv, RecvParams) {
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

BATCHSYS_SYSCALL_BEGIN(recvfrom, RecvfromParams) {
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

BATCHSYS_SYSCALL_BEGIN(write, WriteParams) {
  struct file* const filp = get_cached_filp(context, params->fd);
  if (!filp) {
    result->error = -EINVAL;
    result->result = -1;
  } else {
    result->result =
        kernel_write(filp, params->buf, params->count, &filp->f_pos);
    if (result->result < 0) {
      result->error = -result->result;
      result->result = -1;
    }
  }
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(pwrite, PwriteParams) {
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

BATCHSYS_SYSCALL_BEGIN(writev, WritevParams) {
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

BATCHSYS_SYSCALL_BEGIN(send, SendParams) {
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

BATCHSYS_SYSCALL_BEGIN(sendto, SendtoParams) {
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

BATCHSYS_SYSCALL_BEGIN(connect, ConnectParams) {
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

BATCHSYS_SYSCALL_BEGIN(epoll_ctl, EpollCtlParams) {
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

BATCHSYS_SYSCALL_BEGIN(close_, CloseParams) {
  struct file* filp = get_cached_filp(context, params->fd);
  if (!filp) {
    result->error = -EINVAL;
    result->result = -1;
  } else {
    context_uncache_filp(context, params->fd);
    result->result = filp_close(filp, NULL);
    if (result->result < 0) {
      result->error = -result->result;
      result->result = -1;
    }
  }
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN(socket, SocketParams) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result = sys_socket(params->domain, params->type,
  params->protocol); if (result->result < 0) { result->error =
  -result->result; result->result = -1; } else { context_cache_filp(context,
  result->result);
  }*/
}
BATCHSYS_SYSCALL_END

BATCHSYS_SYSCALL_BEGIN_INTERNAL(socket, _non_block_reuse_, SocketParams) {
  result->error = ENODEV;
  result->result = -1;
  /*result->result = sys_socket(params->domain, params->type,
  params->protocol); if (result->result < 0) { result->error =
  -result->result; result->result = -1; } else { const int ret =
  make_non_blocking_reuse(context, result->result); if (ret < 0) {
      sys_close(result->result);
      result->result = -1;
      result->error = -ret;
    }
  }*/
}
BATCHSYS_SYSCALL_END

static int batchsys_process(struct BatchSysContext* context,
                            struct BatchSysBatch* batch) {
  char* spot = NULL;
  char* end = NULL;
  int ret;
  uint32_t i;
  struct BatchSysProcessParams* params = &batch->params;
  BatchSysCall syscall = NULL;
  struct SyscallParams* syscall_params = NULL;

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

    syscall_params = (struct SyscallParams*)spot;
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
      spot += ret + sizeof(struct SyscallParams);
    } else {
      printk(KERN_ERR "batchsys unrecoverable error: %d\n", ret);
      context->state = kUnrecoverable;
      return -EINVAL;
    }
  }

  return params->incoming.count;
}

static long batchsys_set_file_cache_size(struct BatchSysContext* context,
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
  struct BatchSysContext* context = filp->private_data;
  switch (op) {
    case BATCHSYS_OP_EXECUTE_BATCH:
      struct BatchSysBatch* batch;
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
      struct file* filp;
      if (arg >= context->max_fd) {
        // TODO(bwatling): should probably just close the file here to work
        // seemlessly.
        return -EINVAL;
      }
      filp = context->registered_files[arg];
      context->registered_files[arg] = NULL;
      if (filp) {
        return filp_close(filp, NULL);
      }
      return 0;
    case BATCHSYS_OP_SET_FILE_LIMIT:
      return batchsys_set_file_cache_size(context, arg);
  }
  return -EINVAL;
}

static int batchsys_module_open(struct inode* inode, struct file* filp) {
  struct BatchSysContext* context;
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
  struct BatchSysContext* context = filp->private_data;
  if (context) {
    int count = 0;
    int i;
    for (i = 0; i < context->max_fd; ++i) {
      if (context->registered_files[i]) {
        ++count;
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
  struct BatchSysBatch* batch = vma->vm_private_data;
  printk(KERN_INFO "batchsys free batch %d\n", batch->id);
  free_page((long unsigned int)batch);
}

static struct vm_operations_struct mmap_ops = {
    .close = mmap_close,
};

static int batchsys_mmap(struct file* filp, struct vm_area_struct* vma) {
  struct BatchSysBatch* batch;
  struct BatchSysContext* context = filp->private_data;
  const int spot = atomic_add_return(1, &context->next_batch_id) - 1;
  if (spot >= MAX_BATCHES) {
    printk(KERN_ERR "batchsys too many batches\n");
    return -EINVAL;
  }
  vma->vm_ops = &mmap_ops;
  if (sizeof(struct BatchSysBatch) > PAGE_SIZE) {
    printk(KERN_ERR "batchsys sizeof(struct BatchSysBatch) > PAGE_SIZE\n");
    return -EINVAL;
  }
  batch = (struct BatchSysBatch*)__get_free_page(GFP_KERNEL);
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
                      sizeof(struct BatchSysBatch), PAGE_SHARED)) {
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
         (int)sizeof(struct SyscallParams));
  printk(KERN_INFO "sizeof(BatchSysProcessParams) = %d\n",
         (int)sizeof(struct BatchSysProcessParams));
  return 0;
}

void cleanup_module(void) {
  misc_deregister(&batchsys_device);
  printk(KERN_INFO "batchsys unloaded\n");
}