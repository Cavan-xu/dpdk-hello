#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ring.h>
#include <rte_kni.h>

#include "util_linknode.h"
#include "util_timer.h"
#include "proto_udp.h"
#include "proto_tcp.h"
#include "process_udp.h"
#include "process_tcp.h"
#include "process_arp.h"
#include "process_icmp.h"
#include "util_ring.h"
#include "kni.h"

#define NUM_MBUFS (4096-1)
#define BRUST_SIZE 32

unsigned int RING_SIZE = 1024;

uint32_t gLocalIP = MAKE_IPV4_ADDR(192, 168, 0, 108);

uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

uint8_t gDefaultArpMAc[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool)
{
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "no support eth\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    printf("ifname is: %s\n", dev_info.device->name);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;

    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0 ) {
        rte_exit(EXIT_FAILURE, "set port fail\n");
    }

    struct rte_eth_txconf tx_conf = dev_info.default_txconf;
    tx_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 512, rte_eth_dev_socket_id(gDpdkPortId), &tx_conf) < 0 ) {
        rte_exit(EXIT_FAILURE, "set port fail\n");
    }

    if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
        rte_exit(EXIT_FAILURE, "start port fail\n");
    }

    rte_eth_promiscuous_enable(gDpdkPortId);
}

static int pkt_process(void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    while(1) {
        struct rte_mbuf *mbufs[BRUST_SIZE];
        unsigned int num_recvd =  rte_ring_mc_dequeue_burst(ring->inring, (void **)mbufs, BRUST_SIZE, NULL);

        unsigned i = 0;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

                ng_add_mac(iphdr->src_addr, ehdr->s_addr.addr_bytes);

                if (iphdr->next_proto_id == IPPROTO_UDP) {
                    udp_pkt_in(mbufs[i]);
                    continue;
                }
                if (iphdr->next_proto_id == IPPROTO_TCP) {
                    tcp_pkt_in(mbufs[i]);
                    continue;
                }
            }

            rte_kni_tx_burst(get_global_kni(), &mbufs[i], 1);
            rte_kni_handle_request(get_global_kni());
        }
        
        udp_pkt_out(mbuf_pool);
        tcp_pkt_out(mbuf_pool);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "error with eal init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("test", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "error with mbuf_pool init\n");
    }

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
    char mac_str[18];
    rte_ether_format_addr(mac_str, sizeof(mac_str), (struct rte_ether_addr *)gSrcMac);
    printf("eth0 mac is: %s\n", mac_str);

    ng_init_port(mbuf_pool);
    ng_init_kni(mbuf_pool);

    rte_timer_subsystem_init();

    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

    struct inout_ring *ring = ringInstance();
    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "init ring fail\n");
    }

    if (ring->inring == NULL) {
        ring->inring = rte_ring_create("inring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    if (ring->outring == NULL) {
        ring->outring = rte_ring_create("outring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);

    while (1) {
        // rx
        struct rte_mbuf *rx[BRUST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BRUST_SIZE);
        if (num_recvd > BRUST_SIZE ) {
            rte_exit(EXIT_FAILURE, "error receive from eth\n");
        }
        if (num_recvd > 0) {
            rte_ring_sp_enqueue_burst(ring->inring, (void **)rx, num_recvd, NULL);
        }

        // tx
        struct rte_mbuf *tx[BRUST_SIZE];
        unsigned int nb_tx = rte_ring_sc_dequeue_burst(ring->outring, (void **)tx, BRUST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
            unsigned i = 0;
            for (i = 0; i < nb_tx; i++)
            {
                rte_pktmbuf_free(tx[i]);
            }
        }

        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t diff_tsc;

        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > hz * 10) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
    }

    return 0;
}