#ifndef SCANNERS_HPP
#define SCANNERS_HPP

#include "options.hpp"
#include "rocket.hpp"

class TCPScanner
{
public:
    TCPScanner();
    bool scan_syn(const char *host, uint16_t port); /* Syn scan */
    bool scan_fin(const char *host, uint16_t port); /* Fin scan */
    bool scan_nrm(const char *host, uint16_t port); /* Normal scan */
    bool scan_xms(const char *host, uint16_t port); /* Xmas scan */
    bool scan_nll(const char *host, uint16_t port); /* Null scan */
    bool scan(const char *host, uint16_t port, char scan_type);

    /* Fast scans */
    inline bool fscan_syn(uint16_t port)
    {
        return scan_syn(this->global_target, port);
    }
    inline bool fscan_fin(uint16_t port)
    {
        return scan_fin(this->global_target, port);
    }
    inline bool fscan_nrm(uint16_t port)
    {
        return scan_nrm(this->global_target, port);
    }
    // inline bool fscan_xms(uint16_t port) {
    //  return scan_xms(this->global_target, port);}
    // inline bool fscan_nll(uint16_t port) {
    //    return scan_nll(this->global_target, port);}

    ~TCPScanner();

    char global_target[255];
    Rocket rocket;
    Packet pkt;
    uint8_t buffer[1024];
    TCP tcp, r_tcp; // tcp, and remote tcp -> response
    IP ip, r_ip;    // ip, and remote ip i mean response

    int sport;

#ifdef SPORT_INCREASE
    int inc_counter;
#endif
};

#endif // SCANNERS_HPP
