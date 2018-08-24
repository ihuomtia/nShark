#ifndef STRUCTURES_HPP
#define STRUCTURES_HPP

#include <stdint.h>
#include <stdlib.h>
#include <bits/endian.h>
#include <stdlib.h>

/* Protocol Number */
#define TCP_PROTO_NUM 6

/* TCP Flag bits */
#define FLAG_FIN  0b00000001 // 0x01
#define FLAG_SYN  0b00000010 // 0x02
#define FLAG_RST  0b00000100 // 0x04
#define FLAG_PSH  0b00001000 // 0x08
#define FLAG_ACK  0b00010000 // 0x10
#define FLAG_URG  0b00100000 // 0x20



typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t res1:4;
    uint16_t dataofs:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint16_t dataofs:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#endif
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} tcp_t;


#endif // STRUCTURES_HPP
