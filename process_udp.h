#include <stdio.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#ifndef NG_PROCESS_UDP_H
#define NG_PROCESS_UDP_H

void create_eth_ip_udp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
    uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length);

struct rte_mbuf *ng_udp_pkt_send(struct rte_mempool *mbufpool, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
    uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length);

int udp_pkt_in(struct rte_mbuf *mbuf);

int udp_pkt_out(struct rte_mempool *mbuf_pool);

#endif