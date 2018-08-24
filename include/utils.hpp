#ifndef UTILS_HPP
#define UTILS_HPP

#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define BYTES_PER_COLUMN 8
#define BYTES_PER_ROW    16

namespace utils {
    size_t hexdump(char *, size_t);
    uint16_t checksum(unsigned short *, int);
    uint16_t tcp_checksum(const ip_t *, const tcp_t *);
    bool checkroot();
}

#endif // UTILS_HPP
