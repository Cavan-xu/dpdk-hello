#ifndef NG_PROCESS_TCP_H
#define NG_PROCESS_TCP_H

#include <rte_mbuf.h>

int tcp_pkt_in(struct rte_mbuf *mbuf);

int tcp_pkt_out(struct rte_mempool *mbuf_pool);

#endif 