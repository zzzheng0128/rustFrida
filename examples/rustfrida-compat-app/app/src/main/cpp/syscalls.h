#ifndef RUSTFRIDA_COMPAT_SYSCALLS_H
#define RUSTFRIDA_COMPAT_SYSCALLS_H

#include <stddef.h>
#include <stdint.h>

/* Small arm64 raw-SVC surface used by the demo. */
long rf_openat(int dirfd, const char *path, int flags, int mode);
long rf_readlinkat(int dirfd, const char *path, char *buf, size_t size);
long rf_write(int fd, const void *buf, size_t size);
long rf_read(int fd, void *buf, size_t size);
long rf_close(int fd);
long rf_socket(int domain, int type, int protocol);
long rf_connect(int fd, const void *address, size_t address_len);
long rf_sendto(int fd, const void *buf, size_t size, int flags,
               const void *address, size_t address_len);
long rf_recvfrom(int fd, void *buf, size_t size, int flags,
                 void *address, size_t *address_len);
long rf_mmap(void *address, size_t length, int prot, int flags, int fd, long offset);
long rf_munmap(void *address, size_t length);
long rf_getpid(void);
long rf_gettid(void);
long rf_clock_gettime(int clock_id, void *timespec_ptr);
long rf_getrandom(void *buf, size_t size, unsigned int flags);

/* 返回本 demo raw SVC 封装实际发出的次数，供源端/trace 端对账。 */
uint64_t rf_svc_total(void);

#endif
