#include <stdio.h>
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "proto_udp.h"
#include "util_linknode.h"
#include "common.h"

#define UDP_APP_RECEIVER_SIZE  128
#define RING_SIZE 1024

static struct localhost *lhost = NULL;

extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

struct localhost *get_host_info_head(void)
{
    return lhost;
}

struct localhost *get_host_info_from_fd(int socketfd)
{
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (socketfd == host->fd) {
            return host;
        }
    }

    return NULL;
}

struct localhost *get_host_info_from_ip(uint32_t dip, uint16_t port, uint8_t protocol)
{   
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && protocol == host->protocol) {
            return host;
        }
    }

    return NULL;
}

static void travel_localhost(void)
{   
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        struct in_addr addr;
        addr.s_addr = host->localip;
        char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(mac_str, sizeof(mac_str), (struct rte_ether_addr *)host->localmac);
        printf("ip: %s port: %d mac: %s\n", inet_ntoa(addr), htons(host->localport), mac_str);
    }
}

int ng_socket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol)
{
    int fd = get_fd_from_bitmap();

    struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) {
        printf("init localhost err\n");
        return -1;
    }

    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;
    if(type == SOCK_DGRAM) {
        host->protocol = IPPROTO_UDP;
    }

    host->recvbuf = rte_ring_create("recvbuf", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->recvbuf == NULL) {
        printf("init recvbuf fail\n");
        rte_free(host);
        return -1;
    }

    host->sendbuf = rte_ring_create("sendbuf", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sendbuf == NULL) {
        printf("init sendbuf fail\n");
        rte_ring_free(host->recvbuf);
        rte_free(host);
        return -1;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    LL_ADD(host, lhost);

    return fd;
}

int ng_bind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen)
{
    struct localhost *host = get_host_info_from_fd(sockfd);
    if (host == NULL) {
        return -1;
    }

    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;
}

int ng_close(int fd)
{
    struct localhost *host = get_host_info_from_fd(fd);
    if (host == NULL) {
        return -1;
    }

    LL_REMOVE(host, lhost);

    if (host->recvbuf) {
        rte_ring_free(host->recvbuf);
    }

    if (host->sendbuf) {
        rte_ring_free(host->sendbuf);
    }

    rte_free(host);

    return 0;
}

ssize_t ng_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags, struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addrlen)
{
    struct localhost *host = get_host_info_from_fd(sockfd);
    if (host == NULL) {
        return -1;
    }

    struct offload *ol = NULL;

    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->recvbuf, (void **)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
    saddr->sin_port = ol->sport;
    saddr->sin_addr.s_addr = ol->sip;

    if (len < ol->length) {
        rte_memcpy(buf, ol->data, len);

        unsigned char *ptr = rte_malloc("unsigned char *", ol->length-len, 0);
        rte_memcpy(ptr, ol->data+len, ol->length-len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->recvbuf, ol);
        return len;
    } else {
        rte_memcpy(buf, ol->data, ol->length);
        rte_free(ol->data);
        rte_free(ol);
        return ol->length;
    }
}

ssize_t ng_sendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags, const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addrlen)
{
    struct localhost *host = get_host_info_from_fd(sockfd);
    if (host == NULL) {
        return -1;
    }

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        return -1;
    }

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;
    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;

    struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("ng_sendto: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));

    ol->data = rte_malloc("unsigned char *", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);

    printf("ng_sendto data: %s\n", ol->data);

    rte_ring_mp_enqueue(host->sendbuf, ol);

    return len;
}

int udp_server_entry(__attribute__((unused)) void *arg)
{
    uint32_t gLocalIP = MAKE_IPV4_ADDR(192, 168, 0, 108);

    int connfd = ng_socket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("init conn fd err\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));
    memset(&clientaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8888);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = gLocalIP;

    ng_bind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));
    
    travel_localhost();

    socklen_t *addrlen;
    char buffer[UDP_APP_RECEIVER_SIZE] = {0};
    while(1) {
        if (ng_recvfrom(connfd, buffer, UDP_APP_RECEIVER_SIZE, 0, (struct sockaddr*)&clientaddr, addrlen) < 0 ) {
            continue;
        }
        
        printf("recv from : %s:%d, data: %s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer);

        ng_sendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
    }

    printf("udp stop\n");

    ng_close(connfd);

    return 0;
}
