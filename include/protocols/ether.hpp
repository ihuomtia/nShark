#ifndef ETHER_HPP
#define ETHER_HPP

#include <stdint.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14



typedef struct {
    uint8_t dst[ETHER_ADDR_LEN]; // Destination Mac Address
    uint8_t src[ETHER_ADDR_LEN]; // Source Mac Address
    uint16_t type; // Type of Ethernet packet
} ether_t;


#endif // ETHER_HPP
