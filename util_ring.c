#include <stdio.h>
#include <string.h>

#include <rte_malloc.h>

#include "util_ring.h"

static struct inout_ring *rInst = NULL;

struct inout_ring *ringInstance(void) {
    if (rInst == NULL)
    {
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }

    return rInst;
}