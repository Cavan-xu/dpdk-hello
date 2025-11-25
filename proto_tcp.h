#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ring.h>

#ifndef NG_PROTO_TCP_H
#define NG_PROTO_TCP_H

#define TCP_OPTION_LENGTH 10
#define TCP_INITIAL_WINDOW 14600

#define BUFFER_SIZE 1024

typedef enum _NG_TCP_STATUS {
    NG_TCP_STATUS_CLOSED = 0,

    NG_TCP_STATUS_LISTEN,
    NG_TCP_STATUS_SYN_RCVD,
    NG_TCP_STATUS_SYN_SENT,
    NG_TCP_STATUS_ESTABLISHED,

    NG_TCP_STATUS_FIN_WAIT_1,
    NG_TCP_STATUS_FIN_WAIT_2,
    NG_TCP_STATUS_CLOSING,
    NG_TCP_STATUS_TIME_WAIT,

    NG_TCP_STATUS_CLOSE_WAIT,
    NG_TCP_STATUS_LAST_ACK,
} NG_TCP_STATUS;

struct ng_tcp_stream {
    int fd;

    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    uint16_t proto;

    uint8_t localmac[RTE_ETHER_ADDR_LEN];

    uint32_t snd_next;  //seqnum
    uint32_t recv_next; //acknum

    NG_TCP_STATUS status;

    struct rte_ring *sendbuf;
    struct rte_ring *recvbuf;

    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct ng_tcp_table {
    int count;
    //struct ng_tcp_stream *listen;
    struct ng_tcp_stream *entries;
};

struct ng_tcp_fragment {
	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;
	uint8_t  hdrlen_off;
	uint8_t  tcp_flags;
	uint16_t win;
	uint16_t cksum;
	uint16_t tcp_urp;

    int optlen;
    uint32_t options[TCP_OPTION_LENGTH];

    unsigned char *data;
    int length;
};

struct ng_tcp_stream *ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

struct ng_tcp_table *tcp_table_instance(void);

int ng_tcp_socket(int domain, int type, int protocol);

int ng_tcp_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int ng_tcp_listen (int fd, int n);

int ng_tcp_recv(int fd, void *buf, size_t n, int flags);

int ng_tcp_close(int fd);

int ng_tcp_send(int fd, const void *buf, size_t n, int flags);

int ng_tcp_accept(int fd, struct sockaddr *addr, socklen_t *addr_len);

int tcp_server_entry(void *arg);

#endif