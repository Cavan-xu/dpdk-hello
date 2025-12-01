#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_memcpy.h>
#include <rte_errno.h>

#include "proto_tcp.h"
#include "util_linknode.h"
#include "common.h"

extern unsigned int RING_SIZE;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

static uint32_t TCP_MAX_SEQ = (1ULL << 32) - 1;

static struct ng_tcp_table *tInst = NULL;

struct ng_tcp_table *tcp_table_instance(void)
{
    if (tInst == NULL) {
        tInst = rte_malloc("tcp table", sizeof(struct ng_tcp_table), 0);
        if (tInst == NULL)
        {
            rte_exit(EXIT_FAILURE, "init tcp table fail\n");
        }
        memset(tInst, 0, sizeof(struct ng_tcp_table));
    }

    return tInst;
}

struct ng_tcp_stream *ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    struct ng_tcp_table *table = tcp_table_instance();

    struct ng_tcp_stream *iter = NULL;
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->sip == sip && iter->dip == dip && iter->sport == sport && iter->dport == dport) {
            return iter;
        }
    }

    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) {
            return iter;
        }
    }

    return NULL;
}

static struct ng_tcp_stream *ng_tcp_stream_search_from_fd(int fd) 
{
    struct ng_tcp_table *table = tcp_table_instance();

    struct ng_tcp_stream *iter = NULL;
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->fd == fd) {
            return iter;
        }
    }

    return NULL;
}

static struct ng_tcp_stream *ng_syn_recvd_tcp_stream_from_port(uint32_t dip, uint16_t dport)
{
    struct ng_tcp_table *table = tcp_table_instance();
    struct ng_tcp_stream *iter = NULL;
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->dport == dport && iter->status == NG_TCP_STATUS_SYN_RCVD && iter->dip == dip) {
            return iter;
        }
    }

    return NULL;
}

struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    struct ng_tcp_stream *stream = rte_malloc("tcp stream", sizeof(struct ng_tcp_stream), 0);
    if (stream == NULL) {
        printf("rte_malloc tcp stream fail\n");
        return NULL;
    }
    memset(stream, 0, sizeof(struct ng_tcp_stream));

    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->proto = IPPROTO_TCP;
    stream->fd = -1;

    stream->status = NG_TCP_STATUS_LISTEN;

    stream->sendbuf = rte_ring_create("tcp_sendbuf", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->sendbuf == NULL) {
        printf("init tcp_sendbuf fail: %s\n", rte_strerror(rte_errno));
        rte_free(stream);
        return NULL;
    }

    stream->recvbuf = rte_ring_create("tcp_recvbuf", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->recvbuf == NULL) {
        printf("init tcp_recvbuf fail: %s\n", rte_strerror(rte_errno));
        rte_ring_free(stream->recvbuf);
        rte_free(stream);
        return NULL;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    uint32_t next_seed = time(NULL);
    stream->snd_next = rand_r(&next_seed) & TCP_MAX_SEQ;

    rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    struct ng_tcp_table *table = tcp_table_instance();
    LL_ADD(stream, table->entries);

    return stream;
}

int ng_tcp_socket(__attribute__((unused)) int domain, __attribute__((unused)) int type, __attribute__((unused)) int protocol) {
    int fd = get_fd_from_bitmap();

    struct ng_tcp_stream *stream = rte_malloc("tcp stream", sizeof(struct ng_tcp_stream), 0);
    if (stream == NULL) {
        printf("rte_malloc tcp stream fail\n");
        return 0;
    }
    memset(stream, 0, sizeof(struct ng_tcp_stream));

    stream->fd = fd;
    stream->proto = IPPROTO_TCP;
    stream->next = stream->prev = NULL;

    struct ng_tcp_table *table = tcp_table_instance();
    LL_ADD(stream, table->entries);

    return fd;
}

int ng_tcp_bind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen) {
    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(sockfd);
    if (stream == NULL) {
        return -1;
    }

    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    stream->dip = laddr->sin_addr.s_addr;
    stream->dport = laddr->sin_port;
    rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    stream->status = NG_TCP_STATUS_CLOSED;

    return 0;
}

int ng_tcp_listen(int fd, __attribute__((unused)) int n)
{
    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(fd);
    if (stream == NULL) {
        return -1;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    uint32_t next_seed = time(NULL);
    stream->snd_next = rand_r(&next_seed) & TCP_MAX_SEQ;

    stream->status = NG_TCP_STATUS_LISTEN;

    return 0;
}

int ng_tcp_accept(int fd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addr_len)
{
    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(fd);
    if (stream == NULL) {
        return -1;
    }

    struct ng_tcp_stream *acpt;

    pthread_mutex_lock(&stream->mutex);
    while((acpt = ng_syn_recvd_tcp_stream_from_port(stream->dip, stream->dport)) == NULL) {
        pthread_cond_wait(&stream->cond, &stream->mutex);
    }
    pthread_mutex_unlock(&stream->mutex);

    acpt->fd = get_fd_from_bitmap();

    struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
    saddr->sin_port = acpt->sport;
    saddr->sin_addr.s_addr = acpt->sip;
    rte_memcpy(&saddr->sin_addr.s_addr, &acpt->sip, sizeof(uint32_t));
    acpt->status = NG_TCP_STATUS_ESTABLISHED;

    return acpt->fd;
}

int ng_tcp_recv(int fd, void *buf, size_t n, __attribute__((unused)) int flags)
{
    int length = 0;
    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(fd);
    if (stream == NULL) {
        return -1;
    }

    struct ng_tcp_fragment *fragment = NULL;

    int recv = 0;
    pthread_mutex_lock(&stream->mutex);
    while ((recv = rte_ring_mc_dequeue(stream->recvbuf, (void **)&fragment)) < 0) {
        pthread_cond_wait(&stream->cond, &stream->mutex);
    }
    pthread_mutex_unlock(&stream->mutex);

    if ((size_t)fragment->length > n) {
        rte_memcpy(buf, fragment->data, n);

        size_t i = 0;
        for (i = 0; i < (size_t)fragment->length - n; i++) {
            fragment->data[i] = fragment->data[n + i];
        }
        fragment->length = fragment->length - n;
        length = n;
        
        rte_ring_mp_enqueue(stream->recvbuf, fragment);
    } else if (fragment->length == 0) {
        rte_free(fragment);
        return 0;
    } else {
        rte_memcpy(buf, fragment->data, fragment->length);
        length = fragment->length;

        rte_free(fragment->data);
        fragment->data = NULL;
        rte_free(fragment);
    }

    return length;
}

int ng_tcp_send(int fd, const void *buf, size_t n, __attribute__((unused)) int flags)
{
    int length = 0;

    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(fd);
    if (stream == NULL) {
        return -1;
    }

    struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if (fragment == NULL) {
        return EXIT_FAILURE;
    }
    memset(fragment, 0, sizeof(struct ng_tcp_fragment));

    fragment->dport = stream->sport;
    fragment->sport = stream->dport;
    fragment->acknum = stream->recv_next;
    fragment->seqnum = stream->snd_next;
    fragment->tcp_flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
    fragment->win = TCP_INITIAL_WINDOW;
    fragment->hdrlen_off = 0x50;

    fragment->data = rte_malloc("unsigned char *", n + 1, 0);
    if (fragment->data == NULL) {
        rte_free(fragment);
        return EXIT_FAILURE;
    }
    memset(fragment->data, 0, n + 1);

    rte_memcpy(fragment->data, buf, n);
    fragment->length = n;
    length = fragment->length;

    rte_ring_mp_enqueue(stream->sendbuf, fragment);

    return length;
}

int ng_tcp_close(int fd)
{
    struct ng_tcp_stream *stream = ng_tcp_stream_search_from_fd(fd);
    if (stream == NULL) {
        return -1;
    }

    if (stream->status == NG_TCP_STATUS_LISTEN) {
        struct ng_tcp_table *table = tcp_table_instance();
        LL_REMOVE(stream, table->entries);

        rte_free(stream);
        return 0;
    }

    struct ng_tcp_fragment *fragment = rte_malloc("fragment", sizeof(struct ng_tcp_fragment), 0);
    if (fragment == NULL) {
        return -1;
    }

    fragment->data = NULL;
    fragment->length = 0;
    fragment->sport = stream->dport;
    fragment->dport = stream->sport;
    fragment->seqnum = stream->snd_next;
    fragment->acknum = stream->recv_next;
    fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
    fragment->win = TCP_INITIAL_WINDOW;
    fragment->hdrlen_off = 0x50;

    rte_ring_mp_enqueue(stream->sendbuf, fragment);
    reset_fd_from_bitmap(fd);

    return 0;
}

int tcp_server_entry(__attribute__((unused)) void *arg) 
{
    int listenfd = ng_tcp_socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
        return -1;
    }

    uint32_t gLocalIP = MAKE_IPV4_ADDR(192, 168, 0, 108);

    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = gLocalIP;
    serveraddr.sin_port = htons(8888);
    ng_tcp_bind(listenfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr));

    ng_tcp_listen(listenfd, 10);

    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    socklen_t len = sizeof(client);

    char buf[BUFFER_SIZE] = {0};
    while (1) {

        int connfd = ng_tcp_accept(listenfd, (struct sockaddr *)&client, &len);

        while (1) {
            int n = ng_tcp_recv(connfd, buf, BUFFER_SIZE, 0);
            if (n > 0) {
                printf("receive from tcp: %s\n", buf);
                ng_tcp_send(connfd, buf, n, 0);
            } else if (n == 0) {
                ng_tcp_close(connfd);
                break;
            } else { //nonblock
                break;
            }
        }
    }

    ng_tcp_close(listenfd);
}
