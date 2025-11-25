#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>

#include "process_icmp.h"
#include "util_ring.h"

extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint32_t gLocalIP;

uint16_t ng_icmp_checksum(uint16_t *addr, int count)
{
    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short *)addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

void create_eth_icmp(uint8_t *msg, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip, uint16_t seqnb, uint16_t ident)
{
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth+1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_ICMP;
    rte_memcpy(&ip->src_addr, sip, sizeof(uint32_t));
    rte_memcpy(&ip->dst_addr, dip, sizeof(uint32_t));
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_code = 0;
    icmp->icmp_ident = ident;
    icmp->icmp_seq_nb = seqnb;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ng_icmp_checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));
}

struct rte_mbuf * ng_icmp_send(struct rte_mempool *mbufpool, uint8_t *dst_mac, uint32_t *sip, uint32_t *dip, uint16_t seqnb, uint16_t ident)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +sizeof(struct rte_icmp_hdr);
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

    create_eth_icmp(pktdata, dst_mac, sip, dip, seqnb, ident);

    return mbuf;
}


int icmp_pkt_in(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ehdr =  rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

    struct inout_ring *ring = ringInstance();
    if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST && iphdr->dst_addr == gLocalIP) {
        struct rte_mbuf *sbuf = ng_icmp_send(mbuf_pool, ehdr->s_addr.addr_bytes, &iphdr->dst_addr, &iphdr->src_addr, icmphdr->icmp_seq_nb, icmphdr->icmp_ident);
        if (!sbuf) {
            rte_exit(EXIT_FAILURE, "error init sbuf\n");
        }

        rte_ring_sp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}