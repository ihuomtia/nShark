/**
 * @file packet.hpp
 * @brief Defines a class to send/recv/sniff packets
 *
 * This header provides a set of functions for sending, receiving
 * and sniffing packets.
 *
 * @author ihuomtia
 * @date 24-08-2018
 */


#ifndef PACKET_HPP
#define PACKET_HPP

#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"

#include <stdlib.h>
#include <stdint.h>

#define MAX_PAYLOAD_SIZE 65535

class Packet
{
public:
    Packet();
    ~Packet();

    // Access to payload
    size_t length();
    uint8_t *raw_payload();
    void clear();

    // operators
    void operator=(Packet pkt);

    // utils
    size_t hexdump();
    void checksum();
    void present();
    size_t append(uint8_t *, size_t);
    void setlength(size_t);

    // compile flag
    bool compiled;

    // fields
    tcp_t fields;

protected:
    size_t size = 0;
    uint8_t *payload = new uint8_t[MAX_PAYLOAD_SIZE];
    uint8_t id;
    char repr[16];
};
#endif // PACKET_HPP
