#include <stdio.h>
#include <string.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "process_tcp.h"
#include "proto_tcp.h"
#include "process_arp.h"
#include "util_ring.h"

extern uint8_t gDefaultArpMAc[RTE_ETHER_ADDR_LEN];

static void create_eth_ip_tcp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
    fragment->length + fragment->optlen * sizeof(uint32_t);
    
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth+1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_length - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = fragment->sport;
    tcp->dst_port = fragment->dport;
    tcp->sent_seq = htonl(fragment->seqnum);
    tcp->recv_ack = htonl(fragment->acknum);
    tcp->data_off = fragment->hdrlen_off;
    tcp->rx_win = fragment->win;
    tcp->tcp_urp = fragment->tcp_urp;
    tcp->tcp_flags = fragment->tcp_flags;

    if (fragment->data != NULL) {
        uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
        rte_memcpy(payload, fragment->data, fragment->length);
    }

    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
}

static struct rte_mbuf *ng_tcp_pkt_send(struct rte_mempool *mbufpool, uint32_t sip, uint32_t dip, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
    fragment->length + fragment->optlen * sizeof(uint32_t);
    
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

    create_eth_ip_tcp_pkt(pktdata, sip, dip, srcmac, dstmac, fragment);

    return mbuf;
}

static int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr)
{
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
        if (stream->status == NG_TCP_STATUS_LISTEN) {

            struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);

            struct ng_tcp_fragment *fragment = rte_malloc("tcp fragment", sizeof(struct ng_tcp_fragment), 0);
            if (fragment == NULL) {
                printf("malloc tcp fragment fail\n");
                return EXIT_FAILURE;
            }
            memset(fragment, 0, sizeof(struct ng_tcp_fragment));

            fragment->sport = tcphdr->dst_port;
            fragment->dport = tcphdr->src_port;
            fragment->seqnum = syn->snd_next;
            fragment->acknum = ntohl(tcphdr->sent_seq) + 1;

            fragment->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
            fragment->win = TCP_INITIAL_WINDOW;
            fragment->hdrlen_off = 0x50;
            fragment->data = NULL;
            fragment->length = 0;

            rte_ring_mp_enqueue(syn->sendbuf, fragment);

            syn->recv_next = fragment->acknum;
            syn->status = NG_TCP_STATUS_SYN_RCVD;
        }
    }

    return 0;
}

static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
        if (stream->status == NG_TCP_STATUS_SYN_RCVD) {
            uint32_t acknum = ntohs(tcphdr->recv_ack);
            if (acknum == stream->snd_next + 1) {
                
            }

            stream->status = NG_TCP_STATUS_ESTABLISHED;
            
            struct ng_tcp_stream *listener_stream = ng_tcp_stream_search(0, 0, 0, stream->dport);
            if (listener_stream == NULL) {
                rte_exit(EXIT_FAILURE, "get listener stream fail"); // because accpet will block
            }
            
            pthread_mutex_lock(&listener_stream->mutex);
            pthread_cond_signal(&listener_stream->cond);
            pthread_mutex_unlock(&listener_stream->mutex);
        }
    }

    return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int length)
{
    // uint8_t hdrlen = tcphdr->data_off & 0xF0;
    // hdrlen >>=4;
    // uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
    // printf("payload: %s\n", payload);


    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
        struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if (fragment == NULL) {
            return EXIT_FAILURE;
        }
        memset(fragment, 0, sizeof(struct ng_tcp_fragment));

        fragment->dport = ntohs(tcphdr->dst_port);
        fragment->sport = ntohs(tcphdr->src_port);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = length - hdrlen * 4;
        if (payloadlen > 0) {
            uint8_t *payload = (uint8_t *)(tcphdr) + hdrlen * 4;
            fragment->data = rte_malloc("unsigned char *", payloadlen + 1, 0);
            if (fragment->data == NULL) {
                rte_free(fragment);
                return EXIT_FAILURE;
            }
            memset(fragment->data, 0, payloadlen+1);

            rte_memcpy(fragment->data, payload, payloadlen);
            fragment->length = payloadlen;

            printf("tcp data: %s\n", fragment->data);
        }
        rte_ring_mp_enqueue(stream->recvbuf, fragment);
        
        struct ng_tcp_fragment *ackfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if (ackfragment == NULL) {
            return EXIT_FAILURE;
        }
        memset(ackfragment, 0, sizeof(struct ng_tcp_fragment));
        
        if (stream->recv_next != ntohs(tcphdr->sent_seq)) { //dup ack

        }

        printf("ng_tcp_handle_established remote: %d local: %d\n", ntohl(tcphdr->sent_seq), stream->recv_next);

        stream->recv_next = stream->recv_next + payloadlen;
        stream->snd_next = ntohl(tcphdr->recv_ack);

        ackfragment->dport = tcphdr->src_port;
        ackfragment->sport = tcphdr->dst_port;
        ackfragment->acknum = stream->recv_next;
        ackfragment->seqnum = stream->snd_next;
        ackfragment->tcp_flags = RTE_TCP_ACK_FLAG;
        ackfragment->win = TCP_INITIAL_WINDOW;
        ackfragment->hdrlen_off = 0x50;
        ackfragment->data = NULL;
        ackfragment->length = 0;
        rte_ring_mp_enqueue(stream->sendbuf, ackfragment);

        struct ng_tcp_fragment *echofragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if (echofragment == NULL) {
            return EXIT_FAILURE;
        }
        memset(echofragment, 0, sizeof(struct ng_tcp_fragment));

        echofragment->dport = tcphdr->src_port;
        echofragment->sport = tcphdr->dst_port;
        echofragment->acknum = stream->recv_next;
        echofragment->seqnum = stream->snd_next;
        echofragment->tcp_flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
        echofragment->win = TCP_INITIAL_WINDOW;
        echofragment->hdrlen_off = 0x50;

        uint8_t *payload = (uint8_t *)(tcphdr) + hdrlen * 4;
        echofragment->data = rte_malloc("unsigned char *", payloadlen, 0);
        if (echofragment->data == NULL) {
            rte_free(echofragment);
            return EXIT_FAILURE;
        }
        memset(echofragment->data, 0, payloadlen);

        rte_memcpy(echofragment->data, payload, payloadlen);
        echofragment->length = payloadlen;

        printf("tcp echo data: %s\n", echofragment->data);

        rte_ring_mp_enqueue(stream->sendbuf, echofragment);
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        stream->status = NG_TCP_STATUS_CLOSE_WAIT;
    }

    return 0;
}

int tcp_pkt_in(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

    printf("tcp pkt in, sport: %d dport: %d\n", ntohs(tcphdr->src_port), ntohs(tcphdr->dst_port));

    uint16_t preCkSum = tcphdr->cksum;  
    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
    printf("tcp pkt in cacl preCksum: %d, cur ckSum: %d\n", preCkSum, tcphdr->cksum);
    if (preCkSum != tcphdr->cksum) {
        printf("tcp_pkt_in checksum not correct, ckSum: %d\n", htons(tcphdr->cksum));
        return EXIT_FAILURE;
    }

    struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
    if (stream == NULL) {
        printf("tcp_pkt_in stream not found\n");
        return EXIT_FAILURE;
    }

    switch (stream->status) {
        case NG_TCP_STATUS_CLOSED: //client
            break;
        case NG_TCP_STATUS_LISTEN: //server
            ng_tcp_handle_listen(stream, tcphdr, iphdr);
            break;
        case NG_TCP_STATUS_SYN_SENT: //client
            break;
        case NG_TCP_STATUS_SYN_RCVD: //server
            ng_tcp_handle_syn_rcvd(stream, tcphdr);
            break;
        case NG_TCP_STATUS_ESTABLISHED: //client && server
            ng_tcp_handle_established(stream, tcphdr, (int)(ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr)));
            break;
        case NG_TCP_STATUS_FIN_WAIT_1:  //~clients
            break;
        case NG_TCP_STATUS_FIN_WAIT_2: //~client
            break;
        case NG_TCP_STATUS_CLOSING: //~client
            break;
        case NG_TCP_STATUS_TIME_WAIT:   //~client
            break;
        case NG_TCP_STATUS_CLOSE_WAIT: //~server
            break;
        case NG_TCP_STATUS_LAST_ACK: //~server
            break;
        default:
            printf("not found\n");
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}

int tcp_pkt_out(struct rte_mempool *mbuf_pool)
{
    struct ng_tcp_table *table = tcp_table_instance();
    struct ng_tcp_stream *stream = NULL;

    for (stream = table->entries; stream != NULL; stream = stream->next) {
        struct ng_tcp_fragment *fragment = NULL;

        int nb_send = rte_ring_mc_dequeue(stream->sendbuf, (void **)&fragment);
        if (nb_send < 0) {
            continue;
        }

        uint8_t *dst_mac = ng_get_dst_mac(stream->sip);
        if (dst_mac == NULL) {
            struct rte_mbuf *sbuf = ng_arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMAc, &stream->dip, &stream->sip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
            rte_ring_mp_enqueue(stream->sendbuf, fragment);
        } else {
            struct rte_mbuf *sbuf = ng_tcp_pkt_send(mbuf_pool, stream->dip, stream->sip, stream->localmac, dst_mac, fragment);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->outring, (void **)&sbuf, 1, NULL);
            
            if (fragment->data != NULL) {
                rte_free(fragment->data);
            }
            rte_free(fragment);
        }
    }

    return 0;
}