#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>

#ifndef NG_PROCESS_ARP_H
#define NG_PROCESS_ARP_H

#define ARP_ENTRY_STATUS_DYNAMIC 0
#define ARP_ENTRY_STATUS_STATIC 1

struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t status;
    // 没有内存对齐

    struct arp_entry *next;
    struct arp_entry *prev;
};

struct arp_table {
    struct arp_entry *entries;
    int count;
};

struct arp_table *arp_table_instance(void);

uint8_t *ng_get_dst_mac(uint32_t dip);

void ng_add_mac(uint32_t sip, uint8_t *mac);

void create_eth_arp(uint8_t *msg, uint16_t op_code, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip);

struct rte_mbuf *ng_arp_send(struct rte_mempool *mbufpool, uint16_t op_code, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip);

int arp_request_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf);

int arp_response_pkt_in(struct rte_mbuf *mbuf);

int arp_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf);


#endif