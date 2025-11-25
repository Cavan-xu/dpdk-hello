#include <stdio.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#ifndef NG_PROCESS_ICMP_H
#define NG_PROCESS_ICMP_H

uint16_t ng_icmp_checksum(uint16_t *addr, int count);

void create_eth_icmp(uint8_t *msg, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip, uint16_t seqnb, uint16_t ident);

struct rte_mbuf * ng_icmp_send(struct rte_mempool *mbufpool, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip, uint16_t seqnb, uint16_t ident);

int icmp_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf);

#endif