#include "syscalls.h"

#define RF_NR_OPENAT 56
#define RF_NR_READLINKAT 78
#define RF_NR_CLOSE 57
#define RF_NR_READ 63
#define RF_NR_WRITE 64
#define RF_NR_SOCKET 198
#define RF_NR_CONNECT 203
#define RF_NR_SENDTO 206
#define RF_NR_RECVFROM 207
#define RF_NR_MUNMAP 215
#define RF_NR_MMAP 222
#define RF_NR_CLOCK_GETTIME 113
#define RF_NR_GETPID 172
#define RF_NR_GETTID 178
#define RF_NR_GETRANDOM 278

static volatile uint64_t g_rf_svc_total;

static inline long rf_svc(long nr, long a0, long a1, long a2,
                           long a3, long a4, long a5) {
    __atomic_add_fetch(&g_rf_svc_total, 1, __ATOMIC_RELAXED);
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory", "cc");
    return x0;
}

uint64_t rf_svc_total(void) {
    return __atomic_load_n(&g_rf_svc_total, __ATOMIC_RELAXED);
}

long rf_openat(int dirfd, const char *path, int flags, int mode) {
    return rf_svc(RF_NR_OPENAT, dirfd, (long) path, flags, mode, 0, 0);
}

long rf_readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    return rf_svc(RF_NR_READLINKAT, dirfd, (long) path, (long) buf, (long) size, 0, 0);
}

long rf_write(int fd, const void *buf, size_t size) {
    return rf_svc(RF_NR_WRITE, fd, (long) buf, (long) size, 0, 0, 0);
}

long rf_read(int fd, void *buf, size_t size) {
    return rf_svc(RF_NR_READ, fd, (long) buf, (long) size, 0, 0, 0);
}

long rf_close(int fd) {
    return rf_svc(RF_NR_CLOSE, fd, 0, 0, 0, 0, 0);
}

long rf_socket(int domain, int type, int protocol) {
    return rf_svc(RF_NR_SOCKET, domain, type, protocol, 0, 0, 0);
}

long rf_connect(int fd, const void *address, size_t address_len) {
    return rf_svc(RF_NR_CONNECT, fd, (long) address, (long) address_len, 0, 0, 0);
}

long rf_sendto(int fd, const void *buf, size_t size, int flags,
               const void *address, size_t address_len) {
    return rf_svc(RF_NR_SENDTO, fd, (long) buf, (long) size, flags,
                  (long) address, (long) address_len);
}

long rf_recvfrom(int fd, void *buf, size_t size, int flags,
                 void *address, size_t *address_len) {
    return rf_svc(RF_NR_RECVFROM, fd, (long) buf, (long) size, flags,
                  (long) address, (long) address_len);
}

long rf_mmap(void *address, size_t length, int prot, int flags, int fd, long offset) {
    return rf_svc(RF_NR_MMAP, (long) address, (long) length, prot, flags, fd, offset);
}

long rf_munmap(void *address, size_t length) {
    return rf_svc(RF_NR_MUNMAP, (long) address, (long) length, 0, 0, 0, 0);
}

long rf_getpid(void) {
    return rf_svc(RF_NR_GETPID, 0, 0, 0, 0, 0, 0);
}

long rf_gettid(void) {
    return rf_svc(RF_NR_GETTID, 0, 0, 0, 0, 0, 0);
}

long rf_clock_gettime(int clock_id, void *timespec_ptr) {
    return rf_svc(RF_NR_CLOCK_GETTIME, clock_id, (long) timespec_ptr, 0, 0, 0, 0);
}

long rf_getrandom(void *buf, size_t size, unsigned int flags) {
    return rf_svc(RF_NR_GETRANDOM, (long) buf, (long) size, flags, 0, 0, 0);
}
