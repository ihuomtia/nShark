#ifndef PSDHDR_HPP
#define PSDHDR_HPP

#include "tcp.hpp"

#include <stdint.h>

typedef struct  {
    uint32_t src;
    uint32_t dst;
    uint8_t pad; // Always zero
    uint8_t protocol; /* Padding within protocol */
    uint16_t len;
} psdhdr_t;

#endif // PSDHDR_HPP
