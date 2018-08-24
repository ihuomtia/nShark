/**
 * @file layers.hpp
 * @brief Defines classes for representing network protocol layers (Ethernet, IP, and TCP).
 * @author ihuomtia
 * @date 24-08-2018
 */


#ifndef LAYERS_HPP
#define LAYERS_HPP

#include "packet.hpp"
#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"
#include "protocols/ether.hpp"

#include <string>

/* TCP Layer */
class TCP: public Packet{
public:
    TCP();
    size_t compile();
    size_t frompayload(void *, size_t l);
    Packet operator /(Packet pkt);
    Packet operator /(const char *);

    // for human usage
    void toggleflag(char);
    void setsport(uint16_t );
    void setdport(uint16_t );
    void clearflags();

    // fields
    tcp_t fields;

    //
    void summarize();
};

/* IP Layer */
class IP: public Packet {
public:
    IP();
    size_t frompayload(char *);
    size_t compile();
    Packet operator /(Packet pkt);
    Packet operator /(IP pkt);
    Packet operator /(TCP pkt);

    // for human usage
    void setsrcaddr(const char *);
    void setdstaddr(const char *);

    // fields
    ip_t fields;

    //
    void summarize();
};


/* Ether Layer */
class Ether: public Packet {
public:
    Ether();
    size_t compile();
    //Packet operator /(IP);
    //Packet operator /(Packet);

    // for human usage
    //void setsrcaddr(char *);
    //void setdstaddr(char *);

    // fields
    ether_t fields;
};

#endif // LAYERS_HPP
