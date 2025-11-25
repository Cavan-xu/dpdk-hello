#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include "proto_udp.h"
#include "util_ring.h"
#include "process_arp.h"
#include "process_udp.h"

extern uint8_t gDefaultArpMAc[RTE_ETHER_ADDR_LEN];

void create_eth_ip_udp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
    uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length)
{
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;

    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth+1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip+1);
    udp->src_port = sport;
    udp->dst_port = dport;
    udp->dgram_len = htons(length + sizeof(struct rte_udp_hdr));

    rte_memcpy((uint8_t*)(udp+1), data, length);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
}

struct rte_mbuf *ng_udp_pkt_send(struct rte_mempool *mbufpool, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
    uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length)
{
    // ethhdr(14) + iphdr(20) + udphdr(8) 
    const unsigned total_length = length + 42;
    
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbufpool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "alloc mbuf fail\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    if (!pktdata) {
        rte_exit(EXIT_FAILURE, "init pktdata fail\n");
    }

    create_eth_ip_udp_pkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, data, length);

    return mbuf;
}

int udp_pkt_in(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    struct localhost *host = get_host_info_from_ip(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        printf("get_host_info_from_ip fail\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        printf("malloc offload fail\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    ol->sip = iphdr->src_addr;
    ol->dip = iphdr->dst_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;
    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);
    ol->data = rte_malloc("unsigned char", ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) {
        rte_pktmbuf_free(mbuf);
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, (char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));
    rte_ring_mp_enqueue(host->recvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(mbuf);
    return 0;
}

int udp_pkt_out(struct rte_mempool *mbuf_pool)
{
    struct localhost *host;
    for (host = get_host_info_head(); host != NULL; host = host->next) {   
        struct offload *ol;
        int nb_send = rte_ring_mc_dequeue(host->sendbuf, (void **)&ol);
        if (nb_send < 0) {
            continue;
        }
        
        uint8_t *dst_mac = ng_get_dst_mac(ol->dip);
        if (dst_mac == NULL) {
            struct rte_mbuf *sbuf = ng_arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMAc, &ol->sip, &ol->dip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
            rte_ring_mp_enqueue(host->sendbuf, ol);
        } else {
            struct rte_mbuf *sbuf = ng_udp_pkt_send(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, host->localmac, dst_mac, ol->data, ol->length);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
        }
    }

    return 0;
}