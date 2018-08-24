#ifndef IP_HPP
#define IP_HPP

#include <stdlib.h>
#include <stdint.h>
#include <bits/endian.h>

typedef struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    /* The options start here */
} ip_t;

#endif // IP_HPP
