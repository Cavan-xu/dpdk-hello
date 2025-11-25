#include <stdio.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>
#include <rte_timer.h>

#include "util_ring.h"
#include "process_arp.h"
#include "util_timer.h"

extern uint8_t gDefaultArpMAc[RTE_ETHER_ADDR_LEN];
extern uint32_t gLocalIP;


void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    printf("timer is working\n");

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    int i = 0;
    for (i = 106; i < 107; i++) {   
        struct rte_mbuf *sbuf;
        uint32_t dst_ip = (gLocalIP & 0x00FFFFFF) | (0xFF000000 & (i << 24));
        uint8_t *dst_mac = ng_get_dst_mac(dst_ip);
        if (dst_mac == NULL) {
            sbuf = ng_arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMAc, &gLocalIP, &dst_ip);
        } else {
            sbuf = ng_arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, dst_mac, &gLocalIP, &dst_ip);
        }

        struct in_addr addr;
        addr.s_addr = gLocalIP;
        printf("timer request src: %s\n", inet_ntoa(addr));

        addr.s_addr = dst_ip;
        printf("timer request dst: %s\n", inet_ntoa(addr));

        rte_ring_sp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
    }
}