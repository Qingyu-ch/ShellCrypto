#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int mkstemp(char* template) {
    char* xxx = strstr(template, "XXXXXX");
    if (!xxx) {
        errno = EINVAL;
        return -1;
    }
    static int counter = 0;
    for (int attempt = 0; attempt < 1000; ++attempt) {
        snprintf(xxx, 7, "%05d", (counter++ % 100000));
        int fd = open(template, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}