#include <rte_ethdev.h>

#ifndef NG_UDP_H
#define NG_UDP_H

struct localhost {
    int fd;

    unsigned int status;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    int protocol;

    struct rte_ring *sendbuf;
    struct rte_ring *recvbuf;

    struct localhost *prev;
    struct localhost *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct offload {
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    uint8_t protocol;

    unsigned char *data;
    uint16_t length;
};

struct localhost *get_host_info_head(void);

struct localhost *get_host_info_from_fd(int socketfd);

struct localhost *get_host_info_from_ip(uint32_t dip, uint16_t port, uint8_t protocol);

int udp_server_entry(void *arg);

int ng_socket(int domain, int type, int protocol);

int ng_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t ng_recvfrom(int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t ng_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

int ng_close(int fd);
            

#endif