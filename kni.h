#ifndef NG_KNI
#define NG_KNI

#include <stdio.h>

#include <rte_mempool.h>
#include <rte_kni.h>
#include <rte_mbuf.h>

#define KNI_PKT_SIZE 4096

int ng_init_kni(struct rte_mempool *mbuf_pool);

struct rte_kni *get_global_kni(void);

int kni_pkt_in(struct rte_mbuf *mbuf);

int kni_pkt_out(void);

#endif