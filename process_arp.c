#include <stdio.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "process_arp.h"
#include "util_linknode.h"
#include "util_ring.h"

extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint8_t gDefaultArpMAc[RTE_ETHER_ADDR_LEN];
extern uint32_t gLocalIP;

static struct arp_table *arpt = NULL;

struct arp_table *arp_table_instance(void)
{
    if (arpt == NULL) {
        arpt = rte_malloc("arp table", sizeof(struct arp_table), 0);
        if (arpt == NULL)
        {
            rte_exit(EXIT_FAILURE, "init arp table fail\n");
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }

    return arpt;
}

uint8_t *ng_get_dst_mac(uint32_t dip) 
{
    struct arp_entry *iter;
    struct arp_table *table = arp_table_instance();
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (dip == iter->ip) {
            return iter->hwaddr;
        }
    }

    return NULL;
}

void create_eth_arp(uint8_t *msg, uint16_t op_code, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip)
{
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);

    if (strncmp((char *)dst_mac, (char *)gDefaultArpMAc, RTE_ETHER_ADDR_LEN)) {
        uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
        rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(eth + 1);
    arphdr->arp_hardware = htons(1);
    arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arphdr->arp_plen = 4;
    arphdr->arp_opcode = htons(op_code);

    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    arphdr->arp_data.arp_sip = *sip;
    arphdr->arp_data.arp_tip = *dip;
}

struct rte_mbuf *ng_arp_send(struct rte_mempool *mbufpool, uint16_t op_code, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbufpool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "alloc mbuf fail\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
    if (!pktdata) {
        rte_exit(EXIT_FAILURE, "init pktdata fail\n");
    }

    create_eth_arp(pktdata, op_code, dst_mac, sip, dip);

    return mbuf;
}

int arp_request_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_mbuf *sbuf = ng_arp_send(mbuf_pool, RTE_ARP_OP_REPLY, arphdr->arp_data.arp_sha.addr_bytes, &arphdr->arp_data.arp_tip, &arphdr->arp_data.arp_sip);
    struct inout_ring *ring = ringInstance();
    rte_ring_sp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);

    return 0;
}

int arp_response_pkt_in(struct rte_mbuf *mbuf)
{
    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
    struct arp_table *table = arp_table_instance();
    uint8_t * hwaddr = ng_get_dst_mac(arphdr->arp_data.arp_sip);
    if (hwaddr == NULL) {
        struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
        if (entry) {
            memset(entry, 0, sizeof(struct arp_entry));
            entry->ip = arphdr->arp_data.arp_sip;

            rte_memcpy(entry->hwaddr, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
            entry->status = ARP_ENTRY_STATUS_DYNAMIC;

            LL_ADD(entry, table->entries);
            table->count ++;
        }
    }


    struct arp_entry *iter;
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        struct in_addr addr;
        addr.s_addr = iter->ip;

        char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, (const struct rte_ether_addr *)iter->hwaddr);
        
        printf("ip: %s mac is: %s\n", inet_ntoa(addr), mac_str);
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}

int arp_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

    // struct in_addr addr;
    // addr.s_addr = arphdr->arp_data.arp_sip;
    // printf("arp src: %s\n", inet_ntoa(addr));

    // addr.s_addr = arphdr->arp_data.arp_tip;
    // printf("arp dst: %s\n", inet_ntoa(addr));

    if (arphdr->arp_data.arp_tip != gLocalIP) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }


    if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        arp_request_pkt_in(mbuf_pool, mbuf);
    } else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
        arp_response_pkt_in(mbuf);
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}