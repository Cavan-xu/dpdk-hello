#ifndef NG_UTIL_RING_H
#define NG_UTIL_RING_H

struct inout_ring {
    struct rte_ring *inring;
    struct rte_ring *outring;
};

struct inout_ring *ringInstance(void);

#endif