/**
 * @file rocket.hpp
 * @brief Defines a class to send/recv/sniff packets
 *
 * This header provides a set of functions for sending, receiving
 * and sniffing packets.
 *
 * @author ihuomtia
 * @date 24-08-2018
 */

#ifndef ROCKET_HPP
#define ROCKET_HPP

#include "layers.hpp"
#include "packet.hpp"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>


class Rocket {
public:
    Rocket();
    size_t write(const Packet pkt);
    size_t read(uint8_t *buffer, size_t);
    ~Rocket();

    // Aliases
    inline size_t send(Packet pkt) { return this->write(pkt);} // alias to write


    // packet handling functions
    Ether decode_ethernet(const u_char *); /* TODO */
    IP decode_ip(const u_char *);
    TCP decode_tcp(const u_char *);

    // some other functions
    size_t sniff(uint8_t *, size_t);



protected:
    bool sent;
    int sockfd;
    int rcv_sockfd;
};

#endif // ROCKET_HPP
