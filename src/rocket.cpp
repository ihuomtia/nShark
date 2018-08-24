#include "rocket.hpp"

#include "protocols/ether.hpp"
#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"
#include "options.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>


Rocket::Rocket(){
    sent = false;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int two = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &two, sizeof(two));
}

Rocket::~Rocket(){
    sent = false;
    close(sockfd);
}

size_t Rocket::write(const Packet pkt){
    int  i = 0, one = 1;
    Packet p = pkt;

    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80); // <-- htons(1024) any valid port
    addr.sin_addr.s_addr = 16777343UL; // <-- inet_addr("127.0.0.1"): any valid addr

    i = sendto(sockfd, (void *) p.raw_payload(), p.length(), 0, (struct sockaddr *) &addr, sizeof(addr));
    sent = true;
    return i;
}

size_t Rocket::read(uint8_t *buffer, size_t s){
    int ds;
    socklen_t sl = sizeof(struct sockaddr);
    struct sockaddr sa;

    ds = recvfrom(sockfd, (void *) buffer, s, MSG_DONTWAIT, &sa, &sl);

    return ds;
}

///

Ether Rocket::decode_ethernet(const u_char *hd){ /* TODO */
    Ether new_pkt;

    //new_pkt.fields.src = ether->src;
    //new_pkt.fields.dst = ether->dst;
    //new_pkt.fields.type = ether->type;

    return new_pkt;
}

IP Rocket::decode_ip(const u_char *hd) {
    const ip_t *ip = (const ip_t *) hd;
    IP new_pkt;

    new_pkt.fields.ihl = ip->ihl;
    new_pkt.fields.version = ip->version;
    new_pkt.fields.tos = ip->tos;
    new_pkt.fields.total_length = ip->total_length;
    new_pkt.fields.id = ip->id;
    new_pkt.fields.frag_off = ip->frag_off;
    new_pkt.fields.protocol = ip->protocol;
    new_pkt.fields.checksum = ip->checksum;
    new_pkt.fields.src = ip->src;
    new_pkt.fields.dst = ip->dst;

    new_pkt.setlength(ip->ihl*4);

    return new_pkt;
}

TCP Rocket::decode_tcp(const u_char *hd){
    const tcp_t *tcp = (const tcp_t *) hd;
    TCP new_pkt;

    new_pkt.fields.sport = tcp->sport;
    new_pkt.fields.dport = tcp->dport;
    new_pkt.fields.seq = tcp->seq;
    new_pkt.fields.ack_seq = tcp->ack_seq;
    new_pkt.fields.window = tcp->window;
    new_pkt.fields.checksum = tcp->checksum;
    new_pkt.fields.urg_ptr = tcp->urg_ptr;
    // flags
    new_pkt.fields.fin = tcp->fin;
    new_pkt.fields.syn = tcp->syn;
    new_pkt.fields.rst = tcp->rst;
    new_pkt.fields.psh = tcp->psh;
    new_pkt.fields.ack = tcp->ack;
    new_pkt.fields.urg = tcp->urg;

    // other fieds
    new_pkt.fields.res1 = tcp->res1;
    new_pkt.fields.res2 = tcp->res2;
    new_pkt.fields.dataofs = tcp->dataofs;

    new_pkt.setlength(tcp->dataofs*4);

    return new_pkt;
}
