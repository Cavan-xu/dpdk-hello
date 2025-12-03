#include <stdio.h>
#include <string.h>

#include <rte_kni.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

#include "kni.h"

extern int gDpdkPortId;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

struct rte_kni *kni_handler = NULL;

struct rte_kni *get_global_kni(void)
{
    return kni_handler;
}

// rte_kni_handle_request call
static int ng_config_network_if(uint16_t port_id, uint8_t if_up)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        return -1;
    }

    int ret = 0;
    if (if_up) {
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else {
        rte_eth_dev_stop(port_id);
    }

    if (ret < 0) {
        printf("config network fail\n");
    }

    return ret;
}

int ng_init_kni(struct rte_mempool *mbuf_pool)
{
    if (rte_kni_init(1) == -1) {
        rte_exit(EXIT_FAILURE, "init kni failed\n");
        return -1;
    }

    struct rte_kni_conf conf = {};
    memset(&conf, 0, sizeof(struct rte_kni_conf));
    sprintf(conf.name, "vEth%d", gDpdkPortId);
    conf.group_id = gDpdkPortId;
    conf.mbuf_size = KNI_PKT_SIZE;
    rte_memcpy(conf.mac_addr, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

    // struct rte_eth_dev_info dev_info;
    // memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
    // rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    struct rte_kni_ops ops;
    memset(&ops, 0, sizeof(struct rte_kni_ops));
    ops.port_id = gDpdkPortId;
    ops.config_network_if = ng_config_network_if;

    kni_handler = rte_kni_alloc(mbuf_pool, &conf, NULL);
    if (!kni_handler) {
        rte_exit(EXIT_FAILURE, "init kni handler fail\n");
    }

    return 0;
}