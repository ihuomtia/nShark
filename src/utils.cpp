#include "utils.hpp"

#include "protocols/psdhdr.hpp"
#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <iostream>


size_t utils::hexdump(char *data, size_t n)
{
    size_t i = 0, j, k;
    unsigned int lines;
    for (lines = 0;; lines++)
    {
        if (i >= n)
            break;

        printf("%04x: ", lines * BYTES_PER_ROW);
        for (j = k = 0; i < n && j < BYTES_PER_ROW; i++, j++)
        {
            printf("%02X ", (uint8_t)data[i]);
            if (j == BYTES_PER_COLUMN - 1)
                printf(" "); /* Bcuz j starts from 0 so j=7 actually means that j = 8 starting from 1 */
        }
        if ((lines + 1) * BYTES_PER_ROW - i < BYTES_PER_ROW)
            while (k++ < (((lines + 1) * BYTES_PER_ROW) - i))
                printf("   ");
        printf("\t");
        for (j = i - (i - lines * BYTES_PER_ROW); j < i; j++)
        {
            if (data[j] < 0x20 || data[j] > 0x7f)
                printf(".");
            else
                printf("%c", (char)data[j]);
        }

        printf("\n");
    }
    return i;
}

uint16_t utils::checksum(unsigned short *addr, int len)
{
    uint16_t sum = 0;

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }

    if (len)
        sum += *(uint16_t *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)(~sum);
}

bool utils::checkroot()
{
    if (getuid() > 0)
        return false;
    else
        return true;
}

/* ip_cksum_carry(x) from nmap/libnetutil/netutil.cc */
#define ip_cksum_carry(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/* ip_cksum_add(const void *, size_t, int) from nmap/libdnet-stripped/src/ip-util.cc */
int ip_cksum_add(const void *buf, size_t len, int cksum)
{
    uint16_t *sp = (uint16_t *)buf;
    int n, sn;

    sn = (int)len / 2;
    n = (sn + 15) / 16;

    /* XXX - unroll loop using Duff's device. */
    switch (sn % 16)
    {
    case 0:
        do
        {
            cksum += *sp++;
        case 15:
            cksum += *sp++;
        case 14:
            cksum += *sp++;
        case 13:
            cksum += *sp++;
        case 12:
            cksum += *sp++;
        case 11:
            cksum += *sp++;
        case 10:
            cksum += *sp++;
        case 9:
            cksum += *sp++;
        case 8:
            cksum += *sp++;
        case 7:
            cksum += *sp++;
        case 6:
            cksum += *sp++;
        case 5:
            cksum += *sp++;
        case 4:
            cksum += *sp++;
        case 3:
            cksum += *sp++;
        case 2:
            cksum += *sp++;
        case 1:
            cksum += *sp++;
        } while (--n > 0);
    }
    if (len & 1)
        cksum += htons(*(u_char *)sp << 8);

    return (cksum);
}

/* This function is a modified version of
 * ipv4_pseudoheader_cksum(const struct in_addr *, const struct in_addr *, u8 , u16 , const void *) from nmap/libnetutil/netutil.cc
 */
uint16_t utils::tcp_checksum(const ip_t *ip, const tcp_t *tcp)
{
    psdhdr_t hdr;
    int sum;

    hdr.src = ip->src;
    hdr.dst = ip->dst;
    hdr.pad = 0;
    hdr.protocol = ip->protocol;
    hdr.len = htons(tcp->dataofs * 4);

    /* Get the ones'-complement sum of the pseudo-header. */
    sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
    /* Add it to the sum of the packet. */
    sum = ip_cksum_add((void *)tcp, (tcp->dataofs * 4), sum);

    /* Fold in the carry, take the complement, and return. */
    sum = ip_cksum_carry(sum);
    /* RFC 768: "If the computed  checksum  is zero,  it is transmitted  as all
     * ones (the equivalent  in one's complement  arithmetic).   An all zero
     * transmitted checksum  value means that the transmitter  generated  no
     * checksum" */
    if (0 && hdr.protocol == 17 && sum == 0) // I won't need this right now
        sum = 0xFFFF;

    return sum;
}
