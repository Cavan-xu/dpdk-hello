#include <stdio.h>

#include "common.h"

#define DEFAULT_FD_NUM 3
#define MAX_FD_COUNT 1024

static unsigned char fd_table[MAX_FD_COUNT] = {0};

int get_fd_from_bitmap(void)
{
    int fd = DEFAULT_FD_NUM;
    for (; fd < MAX_FD_COUNT; fd++) {
        int index = fd / 8;
        if ((fd_table[index] & (1 << (fd % 8))) == 0) {
            continue;
        }
        fd_table[index] |= (1 << (fd % 8));
        return fd;
    }

    return -1;
}