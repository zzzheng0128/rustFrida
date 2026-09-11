#include <unistd.h>

/* This library only reads a caller-owned /dev/zero descriptor. */
__attribute__((visibility("default"), noinline))
int sample_read_batch(int fd, unsigned count) {
    char data[64];
    for (unsigned i = 0; i < count; ++i) {
        if (read(fd, data, sizeof(data)) != sizeof(data)) return -1;
    }
    return 0;
}
