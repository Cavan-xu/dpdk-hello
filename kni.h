#ifndef NG_KNI
#define NG_KNI

#include <stdio.h>

#include <rte_mempool.h>

#define KNI_PKT_SIZE 4096

int ng_init_kni(struct rte_mempool *mbuf_pool);

#endif