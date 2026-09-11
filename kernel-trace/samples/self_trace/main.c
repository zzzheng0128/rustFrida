#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*batch_fn)(int, unsigned);

static int wait_for_marker(const char *path, unsigned attempts) {
    for (unsigned i = 0; i < attempts; ++i) {
        if (access(path, F_OK) == 0) return 0;
        usleep(10000);
    }
    fprintf(stderr, "sample marker timeout: %s\n", path);
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    /* Bound the whole sample, including library loading and both handshakes. */
    alarm(40);
    void *a = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *b = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!a || !b) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    batch_fn batch[2] = {(batch_fn)dlsym(a, "sample_read_batch"), (batch_fn)dlsym(b, "sample_read_batch")};
    int fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (!batch[0] || !batch[1] || fd < 0) return 4;
    printf("sample pid=%d ready\n", getpid());
    fflush(stdout);
    if (wait_for_marker(argv[3], 1500) != 0) return 5;
    for (unsigned i = 0; i < 100; ++i) {
        if (batch[i % 2](fd, 64) != 0) return 6;
        usleep(1000);
    }
    printf("sample pid=%d done: 6400 reads, 3200 per library\n", getpid());
    fflush(stdout);
    /* The runner releases these mappings only after the records are written. */
    if (wait_for_marker(argv[4], 2000) != 0) return 7;
    close(fd);
    puts("sample completed: 6400 reads, 3200 per library");
    dlclose(b);
    dlclose(a);
    alarm(0);
    return 0;
}
